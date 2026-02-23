package diff

import (
	"path/filepath"
	"testing"
)

func TestReadNDJSON(t *testing.T) {
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

	if len(baselineRows) != 2 {
		t.Errorf("baseline: expected 2 rows, got %d", len(baselineRows))
	}
	if len(currentRows) != 2 {
		t.Errorf("current: expected 2 rows, got %d", len(currentRows))
	}

	baseByType := GroupByType(baselineRows)
	currByType := GroupByType(currentRows)

	wantKeys := []string{"meta", "probe_failures_summary"}
	for _, k := range wantKeys {
		if _, ok := baseByType[k]; !ok {
			t.Errorf("baseline GroupByType: missing key %q", k)
		}
		if _, ok := currByType[k]; !ok {
			t.Errorf("current GroupByType: missing key %q", k)
		}
	}

	if len(baseByType) != len(wantKeys) {
		t.Errorf("baseline GroupByType: expected %d keys, got %d", len(wantKeys), len(baseByType))
	}
	if len(currByType) != len(wantKeys) {
		t.Errorf("current GroupByType: expected %d keys, got %d", len(wantKeys), len(currByType))
	}
}
