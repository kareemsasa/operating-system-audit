package diff

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const maxLineSize = 1024 * 1024 // 1MB buffer limit since audit output can be large

// Row is a single NDJSON row as a map.
type Row map[string]any

// ReadNDJSON reads an NDJSON file from path. Skips empty lines.
// Returns a clear error with the line number on bad JSON.
func ReadNDJSON(path string) ([]Row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var rows []Row
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, maxLineSize)
	scanner.Buffer(buf, maxLineSize)

	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			msg := err.Error()
			if idx := strings.Index(msg, "\n"); idx >= 0 {
				msg = msg[:idx]
			}
			return nil, fmt.Errorf("invalid JSON at line %d: %s", lineNo, msg)
		}
		rows = append(rows, obj)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return rows, nil
}

// CollectWarningCodes collects unique warning identifiers from all warning rows.
func CollectWarningCodes(rows []Row) map[string]struct{} {
	codes := make(map[string]struct{})
	for _, row := range rows {
		if t, _ := row["type"].(string); t != "warning" {
			continue
		}
		if c, ok := row["code"].(string); ok {
			codes[c] = struct{}{}
		} else if _, ok := row["soft_failures"]; ok {
			codes["soft_failures"] = struct{}{}
		}
	}
	return codes
}

// GroupByType groups rows by their "type" field. For types with multiple rows,
// keeps the last one (most complete).
func GroupByType(rows []Row) map[string]Row {
	byType := make(map[string]Row)
	for _, row := range rows {
		t, ok := row["type"].(string)
		if ok && t != "" {
			byType[t] = row
		}
	}
	return byType
}
