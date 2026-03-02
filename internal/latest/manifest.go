package latest

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// RunMeta holds metadata for a single audit run, emitted by scripts and consumed by the scheduler.
type RunMeta struct {
	RunID     string `json:"run_id"`
	CreatedAt string `json:"created_at"`
	Platform  string `json:"platform"`
	AuditID   string `json:"audit_id"`
	Dir       string `json:"dir"`
	NDJSON    string `json:"ndjson"`
	Report    string `json:"report"`
}

// WriteLatestManifest writes a "latest" manifest for the given audit ID.
// The manifest is written atomically (tmp write + rename) to meta.Dir/.latest.json.
func WriteLatestManifest(auditID string, meta RunMeta) error {
	if auditID == "" || meta.Dir == "" {
		return nil
	}
	manifestPath := filepath.Join(meta.Dir, ".latest.json")
	dir := filepath.Dir(manifestPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmpPath := manifestPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, manifestPath)
}
