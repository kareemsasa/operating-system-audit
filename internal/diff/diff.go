package diff

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	spanSingleShot = "single-shot"
	spanTightBurst = "tight burst"
)

// Run runs the full diff between baseline and current rows, prints human-readable
// Markdown output, and returns true if any changes were detected.
func Run(baselineRows, currentRows []Row) bool {
	baseByType := GroupByType(baselineRows)
	currByType := GroupByType(currentRows)

	hasDeltas := false
	hasDeltas = emitStorageDelta(baseByType["summary"], currByType["summary"]) || hasDeltas
	hasDeltas = emitCountDelta(baseByType["counts"], currByType["counts"]) || hasDeltas
	hasDeltas = emitSecurityConfigDelta(baseByType["security_config"], currByType["security_config"]) || hasDeltas
	hasDeltas = emitHomebrewDelta(baseByType["homebrew_summary"], currByType["homebrew_summary"]) || hasDeltas

	baseWarnings := CollectWarningCodes(baselineRows)
	currWarnings := CollectWarningCodes(currentRows)
	newWarnings := make([]string, 0)
	for c := range currWarnings {
		if _, ok := baseWarnings[c]; !ok {
			newWarnings = append(newWarnings, c)
		}
	}
	hasDeltas = emitNewWarnings(newWarnings) || hasDeltas

	hasDeltas = emitProbeFailuresDelta(baseByType["probe_failures_summary"], currByType["probe_failures_summary"]) || hasDeltas

	if !hasDeltas {
		fmt.Println("No changes detected between baseline and current.")
	}
	return hasDeltas
}

func fmtBytes(n any) string {
	if n == nil {
		return "N/A"
	}
	var v float64
	switch x := n.(type) {
	case float64:
		v = x
	case int:
		v = float64(x)
	case int64:
		v = float64(x)
	default:
		return "N/A"
	}
	v = math.Abs(v)
	units := []string{"B", "K", "M", "G", "T"}
	for _, u := range units {
		if v < 1024 {
			if u == "B" {
				return fmt.Sprintf("%d%s", int(v), u)
			}
			return fmt.Sprintf("%.1f%s", v, u)
		}
		v /= 1024
	}
	return fmt.Sprintf("%.1fP", v)
}

func fmtTsMs(tsMs any) string {
	if tsMs == nil {
		return "N/A"
	}
	var ms float64
	switch x := tsMs.(type) {
	case float64:
		ms = x
	case int:
		ms = float64(x)
	case int64:
		ms = float64(x)
	default:
		return fmt.Sprint(tsMs)
	}
	if ms == 0 {
		return "N/A"
	}
	t := time.UnixMilli(int64(ms)).UTC()
	return t.Format("2006-01-02 15:04:05")
}

// SpanLabel returns "single-shot" | "tight burst" | "span" for probe failure display.
func SpanLabel(count int, durMs any) string {
	if count == 1 {
		return spanSingleShot
	}
	d := toFloat64(durMs)
	if d == 0 {
		return spanTightBurst
	}
	return "span"
}

// SpanFormat formats span for display. Avoids (0.0/s) when duration rounds weirdly.
func SpanFormat(count int, durMs, rate any, firstTs, lastTs any, fmtTs func(any) string) string {
	label := SpanLabel(count, durMs)
	if label == spanSingleShot {
		return spanSingleShot
	}
	if label == spanTightBurst {
		return spanTightBurst
	}
	span := fmt.Sprintf("%s → %s", fmtTs(firstTs), fmtTs(lastTs))
	durSec := toFloat64(durMs) / 1000
	r := toFloat64(rate)
	if durSec >= 1 && r > 0 {
		return fmt.Sprintf("%s (%.2f/s)", span, r)
	}
	return span
}

func toFloat64(v any) float64 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return 0
	}
}

func toInt(v any) int {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	default:
		return 0
	}
}

func getMap(row Row, key string) map[string]any {
	if row == nil {
		return nil
	}
	m, _ := row[key].(map[string]any)
	return m
}

func getSlice(row Row, key string) []any {
	if row == nil {
		return nil
	}
	s, _ := row[key].([]any)
	return s
}

func exitCodesDelta(baseEC, currEC map[string]any) map[string]int {
	allCodes := make(map[string]struct{})
	for k := range baseEC {
		allCodes[k] = struct{}{}
	}
	for k := range currEC {
		allCodes[k] = struct{}{}
	}
	delta := make(map[string]int)
	for c := range allCodes {
		curr := toInt(currEC[c])
		base := toInt(baseEC[c])
		d := curr - base
		delta[c] = d
	}
	return delta
}

func normExitCodes(ec map[string]any) map[int]int {
	if ec == nil {
		return nil
	}
	out := make(map[int]int)
	for k, v := range ec {
		var kk int
		if _, err := fmt.Sscanf(k, "%d", &kk); err == nil {
			out[kk] = toInt(v)
		}
	}
	return out
}

func mapsEqual(a, b map[int]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func probeFailureIsChanged(probe string, baseIt, currIt Row) bool {
	if baseIt == nil || currIt == nil {
		return true
	}
	if toInt(baseIt["count"]) != toInt(currIt["count"]) {
		return true
	}
	baseEC := getMap(baseIt, "exit_codes")
	currEC := getMap(currIt, "exit_codes")
	if !mapsEqual(normExitCodes(baseEC), normExitCodes(currEC)) {
		return true
	}
	baseState := ExpectedState(probe, baseEC)
	currState := ExpectedState(probe, currEC)
	return baseState != currState
}

func probeSortKey(probe, status string) (int, int, string) {
	sev := 2
	if s, ok := SeverityOrder[ProbeSeverity(probe)]; ok {
		sev = s
	}
	statusOrder := map[string]int{"new": 0, "resolved": 1, "changed": 2}
	so := 3
	if s, ok := statusOrder[status]; ok {
		so = s
	}
	return sev, so, probe
}

type probeEntry struct {
	status  string
	probe   string
	baseIt  Row
	currIt  Row
}

func buildProbeFailureEntries(basePF, currPF Row) []probeEntry {
	baseItems := getSlice(basePF, "items")
	currItems := getSlice(currPF, "items")

	baseProbes := make(map[string]Row)
	for _, it := range baseItems {
		row, _ := it.(map[string]any)
		if row != nil {
			if p, ok := row["probe"].(string); ok {
				baseProbes[p] = row
			}
		}
	}
	currProbes := make(map[string]Row)
	for _, it := range currItems {
		row, _ := it.(map[string]any)
		if row != nil {
			if p, ok := row["probe"].(string); ok {
				currProbes[p] = row
			}
		}
	}

	var newProbes, resolvedProbes, changedProbes []string
	for p := range currProbes {
		if _, ok := baseProbes[p]; !ok {
			newProbes = append(newProbes, p)
		}
	}
	for p := range baseProbes {
		if _, ok := currProbes[p]; !ok {
			resolvedProbes = append(resolvedProbes, p)
		}
	}
	for p := range baseProbes {
		if _, ok := currProbes[p]; ok {
			if probeFailureIsChanged(p, baseProbes[p], currProbes[p]) {
				changedProbes = append(changedProbes, p)
			}
		}
	}

	sortProbes := func(probes []string, status string) {
		sort.Slice(probes, func(i, j int) bool {
			si, soi, pi := probeSortKey(probes[i], status)
			sj, soj, pj := probeSortKey(probes[j], status)
			if si != sj {
				return si < sj
			}
			if soi != soj {
				return soi < soj
			}
			return pi < pj
		})
	}
	sortProbes(newProbes, "new")
	sortProbes(resolvedProbes, "resolved")
	sortProbes(changedProbes, "changed")

	var entries []probeEntry
	for _, p := range newProbes {
		entries = append(entries, probeEntry{"new", p, nil, currProbes[p]})
	}
	for _, p := range resolvedProbes {
		entries = append(entries, probeEntry{"resolved", p, baseProbes[p], nil})
	}
	for _, p := range changedProbes {
		entries = append(entries, probeEntry{"changed", p, baseProbes[p], currProbes[p]})
	}
	return entries
}

func formatExitCodes(ec map[string]any) string {
	if len(ec) == 0 {
		return ""
	}
	var keys []int
	for k := range ec {
		var kk int
		if _, err := fmt.Sscanf(k, "%d", &kk); err == nil {
			keys = append(keys, kk)
		}
	}
	sort.Ints(keys)
	var parts []string
	for _, k := range keys {
		v := toInt(ec[strconv.Itoa(k)])
		parts = append(parts, fmt.Sprintf("%d:%d", k, v))
	}
	return strings.Join(parts, ",")
}

func formatExitCodesDelta(delta map[string]int) string {
	var keys []int
	for k := range delta {
		var kk int
		if _, err := fmt.Sscanf(k, "%d", &kk); err == nil {
			keys = append(keys, kk)
		}
	}
	sort.Ints(keys)
	var parts []string
	for _, k := range keys {
		v := delta[strconv.Itoa(k)]
		if v != 0 {
			sign := ""
			if v > 0 {
				sign = "+"
			}
			parts = append(parts, fmt.Sprintf("%d:%s%d", k, sign, v))
		}
	}
	return strings.Join(parts, ", ")
}

func formatProbeEntryNew(probe string, currIt Row) string {
	c := toInt(currIt["count"])
	ec := getMap(currIt, "exit_codes")
	spanStr := SpanFormat(
		c,
		currIt["duration_ms"],
		currIt["failure_rate"],
		currIt["first_ts_ms"],
		currIt["last_ts_ms"],
		fmtTsMs,
	)
	expSuffix := ExpectedSuffix(probe, ec)
	return fmt.Sprintf("  + %s failed %d× (%s), exit_codes: {%s}%s", probe, c, spanStr, formatExitCodes(ec), expSuffix)
}

func formatProbeEntryResolved(probe string, baseIt Row) string {
	c := toInt(baseIt["count"])
	ec := getMap(baseIt, "exit_codes")
	expSuffix := ExpectedSuffix(probe, ec)
	return fmt.Sprintf("  - %s resolved (was %d×, exit_codes: {%s})%s", probe, c, formatExitCodes(ec), expSuffix)
}

func formatProbeEntryChanged(probe string, baseIt, currIt Row) string {
	bc := toInt(baseIt["count"])
	cc := toInt(currIt["count"])
	ecDelta := exitCodesDelta(getMap(baseIt, "exit_codes"), getMap(currIt, "exit_codes"))
	deltaStr := formatExitCodesDelta(ecDelta)
	expSuffix := ExpectedSuffix(probe, getMap(currIt, "exit_codes"))
	if deltaStr != "" {
		return fmt.Sprintf("  ~ %s %d×→%d×, exit_codes: %s%s", probe, bc, cc, deltaStr, expSuffix)
	}
	return fmt.Sprintf("  ~ %s %d×→%d×%s", probe, bc, cc, expSuffix)
}

func emitStorageDelta(baseSum, currSum Row) bool {
	storageFields := []string{"home_bytes", "downloads_bytes", "desktop_bytes", "trash_bytes"}
	if baseSum == nil || currSum == nil {
		return false
	}
	var deltas []struct {
		field string
		b, c  any
		delta float64
		pct   float64
	}
	for _, f := range storageFields {
		b, c := baseSum[f], currSum[f]
		if b == nil || c == nil {
			continue
		}
		bf, cf := toFloat64(b), toFloat64(c)
		delta := cf - bf
		if delta == 0 {
			continue
		}
		pct := 0.0
		if bf != 0 {
			pct = delta / bf * 100
		}
		deltas = append(deltas, struct {
			field string
			b, c  any
			delta float64
			pct   float64
		}{strings.TrimSuffix(f, "_bytes"), b, c, delta, pct})
	}
	if len(deltas) == 0 {
		return false
	}
	fmt.Println("## Storage delta")
	for _, d := range deltas {
		sign := ""
		if d.delta >= 0 {
			sign = "+"
		}
		fmt.Printf("  %s: %s → %s (%s%s, %+.1f%%)\n", d.field, fmtBytes(d.b), fmtBytes(d.c), sign, fmtBytes(d.delta), d.pct)
	}
	fmt.Println()
	return true
}

func emitCountDelta(baseCounts, currCounts Row) bool {
	countFields := []string{"large_files", "node_modules", "broken_symlinks", "git_repos", "venv_cache"}
	if baseCounts == nil || currCounts == nil {
		return false
	}
	var deltas []struct {
		field string
		b, c  int
		delta int
	}
	for _, f := range countFields {
		b, c := toInt(baseCounts[f]), toInt(currCounts[f])
		if c-b != 0 {
			deltas = append(deltas, struct {
				field string
				b, c  int
				delta int
			}{f, b, c, c - b})
		}
	}
	if len(deltas) == 0 {
		return false
	}
	fmt.Println("## Count changes")
	for _, d := range deltas {
		sign := ""
		if d.delta >= 0 {
			sign = "+"
		}
		fmt.Printf("  %s: %d → %d (%s%d)\n", d.field, d.b, d.c, sign, d.delta)
	}
	fmt.Println()
	return true
}

func emitSecurityConfigDelta(baseSec, currSec Row) bool {
	secFields := []string{"filevault", "sip", "gatekeeper", "firewall"}
	if baseSec == nil || currSec == nil {
		return false
	}
	var changes []struct {
		field    string
		b, c     bool
	}
	for _, f := range secFields {
		b, c := baseSec[f], currSec[f]
		if b == nil || c == nil {
			continue
		}
		bb := toBool(b)
		cc := toBool(c)
		if bb != cc {
			changes = append(changes, struct {
				field string
				b, c  bool
			}{f, bb, cc})
		}
	}
	if len(changes) == 0 {
		return false
	}
	fmt.Println("## Security config changes")
	for _, ch := range changes {
		bStr, cStr := "off", "off"
		if ch.b {
			bStr = "on"
		}
		if ch.c {
			cStr = "on"
		}
		fmt.Printf("  %s: %s → %s\n", ch.field, bStr, cStr)
	}
	fmt.Println()
	return true
}

func toBool(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case int:
		return x != 0
	default:
		return false
	}
}

func emitHomebrewDelta(baseBrew, currBrew Row) bool {
	if baseBrew == nil || currBrew == nil {
		return false
	}
	var deltas []struct {
		field string
		b, c  int
		delta int
	}
	for _, f := range []string{"formulae", "casks"} {
		b, c := toInt(baseBrew[f]), toInt(currBrew[f])
		if c-b != 0 {
			deltas = append(deltas, struct {
				field string
				b, c  int
				delta int
			}{f, b, c, c - b})
		}
	}
	if len(deltas) == 0 {
		return false
	}
	fmt.Println("## Homebrew delta")
	for _, d := range deltas {
		sign := ""
		if d.delta >= 0 {
			sign = "+"
		}
		fmt.Printf("  %s: %d → %d (%s%d)\n", d.field, d.b, d.c, sign, d.delta)
	}
	fmt.Println()
	return true
}

func emitNewWarnings(codes []string) bool {
	if len(codes) == 0 {
		return false
	}
	sort.Strings(codes)
	fmt.Println("## New warnings")
	for _, c := range codes {
		fmt.Printf("  - %s\n", c)
	}
	fmt.Println()
	return true
}

func topicSortKey(topic string) int {
	for i, t := range TopicOrder {
		if t == topic {
			return i
		}
	}
	return 99
}

func emitProbeFailuresDelta(basePF, currPF Row) bool {
	entries := buildProbeFailureEntries(basePF, currPF)
	fmt.Println("## Probe failures delta")
	if len(entries) == 0 {
		fmt.Println("  No changes detected")
		fmt.Println()
		return false
	}
	byTopic := make(map[string][]probeEntry)
	for _, e := range entries {
		topic := ProbeTopic(e.probe)
		byTopic[topic] = append(byTopic[topic], e)
	}
	var topics []string
	for t := range byTopic {
		topics = append(topics, t)
	}
	sort.Slice(topics, func(i, j int) bool {
		ki, kj := topicSortKey(topics[i]), topicSortKey(topics[j])
		if ki != kj {
			return ki < kj
		}
		return topics[i] < topics[j]
	})
	for _, topic := range topics {
		items := byTopic[topic]
		fmt.Printf("\n### %s\n", topic)
		for _, e := range items {
			switch e.status {
			case "new":
				fmt.Println(formatProbeEntryNew(e.probe, e.currIt))
			case "resolved":
				fmt.Println(formatProbeEntryResolved(e.probe, e.baseIt))
			default:
				fmt.Println(formatProbeEntryChanged(e.probe, e.baseIt, e.currIt))
			}
		}
	}
	fmt.Println()
	return true
}
