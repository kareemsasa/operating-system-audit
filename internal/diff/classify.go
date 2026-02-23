package diff

import (
	"fmt"
	"strings"
)

// Severity: prefix patterns first (data-driven), then exact overrides.
// config.* = security-critical, identity.dscl_* / network.ifconfig_* = load-bearing, etc.
var probeSeverityPrefix = []struct {
	prefix string
	sev    string
}{
	{"config.", "high"},
	{"network.defaults_", "high"},
	{"network.socketfilterfw_", "high"},
	{"identity.dscl_", "medium"},
	{"identity.dseditgroup_", "medium"},
	{"network.ifconfig_", "medium"},
	{"network.lsof_", "medium"},
	{"network.scutil_", "medium"},
	{"execution.launchctl_", "medium"},
	{"execution.ps_", "low"},
	{"persistence.", "medium"},
}

var probeSeverityExact = map[string]string{
	"network.socketfilterfw_stealth": "high",
}

// Probes that commonly fail with these codes in non-interactive contexts (permission, TCC, etc).
// When all exit_codes match expected, severity can be downgraded for display.
var probeExpectedExitCodes = map[string]map[int]struct{}{
	"config.fdesetup_status":                 {15: {}, 1: {}},
	"config.defaults_firewall_globalstate":   {1: {}},
	"config.defaults_screen_lock_delay":     {1: {}},
	"network.defaults_firewall_globalstate":  {1: {}},
	"identity.dscl_list_users":               {70: {}, 1: {}},
	"identity.dseditgroup_checkmember":       {1: {}},
}

// Topic for grouping (probe prefix -> display name). Order = display priority.
var probeTopic = map[string]string{
	"config.":      "Security",
	"network.":     "Network",
	"identity.":    "Identity",
	"storage.":     "Storage",
	"execution.":   "Execution",
	"persistence.": "Persistence",
}

// TopicOrder defines display priority for grouping probe failures.
var TopicOrder = []string{"Security", "Network", "Identity", "Storage", "Execution", "Persistence", "Other"}

// SeverityOrder maps severity to sort priority (lower = higher priority).
var SeverityOrder = map[string]int{"high": 0, "medium": 1, "low": 2}

// ProbeSeverity returns the severity for a probe: "high", "medium", or "low".
func ProbeSeverity(probe string) string {
	if sev, ok := probeSeverityExact[probe]; ok {
		return sev
	}
	for _, p := range probeSeverityPrefix {
		if strings.HasPrefix(probe, p.prefix) {
			return p.sev
		}
	}
	return "low"
}

// ProbeTopic derives topic from probe prefix. Falls back to "Other" only if unclassifiable.
func ProbeTopic(probe string) string {
	for prefix, topic := range probeTopic {
		if strings.HasPrefix(probe, prefix) {
			return topic
		}
	}
	return "Other"
}

// ExpectedState returns "expected" | "mixed" | "unexpected".
// Mixed = some match, some don't (regression hiding in noise).
// exitCodes is a map of exit code (string key) to count, e.g. {"70": 1, "1": 1}.
func ExpectedState(probe string, exitCodes map[string]any) string {
	expected := probeExpectedExitCodes[probe]
	if len(expected) == 0 {
		return "unexpected"
	}
	codes := make(map[int]struct{})
	for k := range exitCodes {
		var c int
		if _, err := fmt.Sscanf(k, "%d", &c); err == nil {
			codes[c] = struct{}{}
		}
	}
	if len(codes) == 0 {
		return "unexpected"
	}
	// codes <= expected (all codes are subset of expected)
	allInExpected := true
	hasOverlap := false
	for c := range codes {
		if _, ok := expected[c]; ok {
			hasOverlap = true
		} else {
			allInExpected = false
		}
	}
	if allInExpected {
		return "expected"
	}
	if hasOverlap {
		return "mixed"
	}
	return "unexpected"
}

// ExpectedSuffix returns display suffix: " (expected)" | " (mixed)" | "".
func ExpectedSuffix(probe string, exitCodes map[string]any) string {
	state := ExpectedState(probe, exitCodes)
	switch state {
	case "expected":
		return " (expected)"
	case "mixed":
		return " (mixed)"
	default:
		return ""
	}
}
