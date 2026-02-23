package diff

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRun_WithFixtures_HasDeltasAndExpectedFormatting(t *testing.T) {
	base := filepath.Join("..", "..", "tests", "fixtures", "probe_diff_baseline.ndjson")
	curr := filepath.Join("..", "..", "tests", "fixtures", "probe_diff_current.ndjson")

	baselineRows, err := ReadNDJSON(base)
	if err != nil {
		t.Fatalf("ReadNDJSON(baseline): %v", err)
	}
	currentRows, err := ReadNDJSON(curr)
	if err != nil {
		t.Fatalf("ReadNDJSON(current): %v", err)
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	hasDeltas := Run(baselineRows, currentRows)

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	if !hasDeltas {
		t.Error("Run with fixture data must return true (changes exist)")
	}

	// Key strings from Python test_probe_diff_formatting
	if out == "" {
		t.Fatal("expected non-empty output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("## Probe failures delta")) {
		t.Error("output must contain '## Probe failures delta'")
	}
	// Tight burst: count>1, duration_ms=0 (network.ifconfig_iface: 5×, duration_ms=0)
	if !bytes.Contains(buf.Bytes(), []byte("tight burst")) {
		t.Error("expected 'tight burst' for network.ifconfig_iface (5×, duration_ms=0)")
	}
	// Span + rate: duration>=1s, rate shown (network.ifconfig_list: 12× over 2.1s, rate ~5.71)
	if !bytes.Contains(buf.Bytes(), []byte("5.71")) {
		t.Error("expected rate for network.ifconfig_list (12× over 2.1s)")
	}
	// (0.0/s) guard: sub-second duration should NOT show rate
	if bytes.Contains(buf.Bytes(), []byte("(0.0/s)")) {
		t.Error("should not show (0.0/s) for sub-second duration")
	}
	// Mixed exit codes (config.fdesetup_status with {1,255})
	if !bytes.Contains(buf.Bytes(), []byte("(mixed)")) {
		t.Error("expected (mixed) for config.fdesetup_status with {1,255}")
	}
	// Expected (identity.dscl_list_users)
	if !bytes.Contains(buf.Bytes(), []byte("(expected)")) {
		t.Error("expected (expected) for identity.dscl_list_users")
	}
	// Topic grouping: identity probe under Identity
	if !bytes.Contains(buf.Bytes(), []byte("### Identity")) {
		t.Error("expected ### Identity section")
	}
	if !bytes.Contains(buf.Bytes(), []byte("identity.dscl_list_users")) {
		t.Error("expected identity.dscl_list_users in output")
	}
	// Ensure identity probe is under Identity section
	lines := bytes.Split(buf.Bytes(), []byte("\n"))
	inIdentity := false
	for _, line := range lines {
		if bytes.Contains(line, []byte("### Identity")) {
			inIdentity = true
			continue
		}
		if inIdentity {
			if bytes.HasPrefix(bytes.TrimSpace(line), []byte("###")) {
				break
			}
			if bytes.Contains(line, []byte("identity.")) {
				return // found identity probe under Identity section
			}
		}
	}
	t.Error("identity.dscl_list_users should be under ### Identity section")
}

func TestRun_NoOpChange_NotEmitted(t *testing.T) {
	// Identical probe in both: count 22, exit_codes {1:22}. Must NOT emit ~ Changed.
	meta := Row{"type": "meta", "run_id": "x", "timestamp": "2026-02-22T10:00:00Z"}
	item := Row{
		"probe":        "config.defaults_firewall_globalstate",
		"count":        22,
		"first_ts_ms":  1708600000000,
		"last_ts_ms":   1708600000000,
		"duration_ms":  0,
		"failure_rate": 22.0,
		"exit_codes":   map[string]any{"1": 22},
	}
	basePF := Row{"type": "probe_failures_summary", "run_id": "base", "items": []any{item}}
	currPF := Row{"type": "probe_failures_summary", "run_id": "curr", "items": []any{copyRow(item)}}

	baselineRows := []Row{meta, basePF}
	currentRows := []Row{meta, currPF}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	hasDeltas := Run(baselineRows, currentRows)

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	if hasDeltas {
		t.Error("Run with identical probe data must return false (no changes)")
	}
	if bytes.Contains([]byte(out), []byte("~ config.defaults_firewall_globalstate")) {
		t.Error("No-op change (22×→22×, same exit_codes) must not emit ~ Changed")
	}
	if !bytes.Contains([]byte(out), []byte("No changes detected")) {
		t.Error("expected 'No changes detected' in output")
	}
}

func copyRow(r Row) Row {
	data, _ := json.Marshal(r)
	var out Row
	json.Unmarshal(data, &out)
	return out
}
