package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateManifest(t *testing.T) {
	tmp := t.TempDir()
	auditDir := filepath.Join(tmp, "audit", "mac")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(auditDir, "script.sh")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		repoRoot string
		m        manifest
		wantErr  string
	}{
		{
			name:     "valid manifest",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "valid", Display: "Valid", OSExec: map[string][]string{"mac": []string{"audit/mac/script.sh"}}},
				},
			},
		},
		{
			name:     "valid single command with mac and linux targets",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "full", Display: "Full", OSExec: map[string][]string{
						"mac":   []string{"audit/mac/script.sh"},
						"linux": []string{"audit/mac/script.sh"},
					}},
				},
			},
		},
		{
			name:     "missing ID",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "", Display: "X", OSExec: map[string][]string{"mac": []string{"audit/mac/script.sh"}}},
				},
			},
			wantErr: "id is required",
		},
		{
			name:     "duplicate ID",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "dup", Display: "A", OSExec: map[string][]string{"mac": []string{"audit/mac/script.sh"}}},
					{ID: "dup", Display: "B", OSExec: map[string][]string{"linux": []string{"audit/mac/script.sh"}}},
				},
			},
			wantErr: "duplicate id",
		},
		{
			name:     "invalid OS",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "x", Display: "X", OSExec: map[string][]string{"solaris": []string{"audit/mac/script.sh"}}},
				},
			},
			wantErr: "unsupported OS key",
		},
		{
			name:     "missing os_exec targets",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "x", Display: "X", OSExec: map[string][]string{}},
				},
			},
			wantErr: "os_exec must contain at least one target",
		},
		{
			name:     "empty os_exec {} fails validation",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "empty", Display: "Empty", OSExec: map[string][]string{}},
				},
			},
			wantErr: "os_exec must contain at least one target",
		},
		{
			name:     "non-existent exec path",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "x", Display: "X", OSExec: map[string][]string{"mac": []string{"audit/mac/nonexistent.sh"}}},
				},
			},
			wantErr: "does not exist",
		},
		{
			name:     "empty commands",
			repoRoot: tmp,
			m:        manifest{Commands: []auditCommand{}},
			wantErr:  "at least one entry",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateManifest(tt.repoRoot, tt.m)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("validateManifest() = nil, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("validateManifest() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("validateManifest() = %v", err)
			}
		})
	}
}

func TestParseRunArgs(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantID        string
		wantPass      []string
		wantPrintMeta bool
		wantErr       bool
		wantErrMsg    string
	}{
		{"no args (error)", []string{}, "", nil, false, true, "missing command id"},
		{"id only", []string{"full"}, "full", nil, false, false, ""},
		{"id + -- + passthrough", []string{"full", "--", "-x", "y"}, "full", []string{"-x", "y"}, false, false, ""},
		{"id + --print-run-meta", []string{"full", "--print-run-meta"}, "full", nil, true, false, ""},
		{"id + --print-run-meta + -- + passthrough", []string{"full", "--print-run-meta", "--", "-x"}, "full", []string{"-x"}, true, false, ""},
		{"id + extra without -- (error)", []string{"full", "extra"}, "", nil, false, true, "pass-through"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, pass, printMeta, err := parseRunArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRunArgs() = %q, %v, %v, nil; want error containing %q", id, pass, printMeta, tt.wantErrMsg)
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("parseRunArgs() error = %v, want containing %q", err, tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("parseRunArgs() = %v", err)
				return
			}
			if id != tt.wantID {
				t.Errorf("parseRunArgs() id = %q, want %q", id, tt.wantID)
			}
			if !sliceEqual(pass, tt.wantPass) {
				t.Errorf("parseRunArgs() passthrough = %v, want %v", pass, tt.wantPass)
			}
			if printMeta != tt.wantPrintMeta {
				t.Errorf("parseRunArgs() printMeta = %v, want %v", printMeta, tt.wantPrintMeta)
			}
		})
	}
}

func TestDetectOS(t *testing.T) {
	got, err := detectOS()
	if err != nil {
		t.Fatalf("detectOS() = %v", err)
	}
	want := map[string]string{
		"darwin":  "mac",
		"linux":   "linux",
		"windows": "windows",
	}
	if expected, ok := want[runtime.GOOS]; ok {
		if got != expected {
			t.Errorf("detectOS() = %q, want %q (GOOS=%s)", got, expected, runtime.GOOS)
		}
	} else {
		t.Logf("detectOS() = %q on unsupported GOOS=%s (expected to fail on other platforms)", got, runtime.GOOS)
	}
}

func TestCommandsForCurrentOS(t *testing.T) {
	macLinux := auditCommand{ID: "both", Display: "Both", OSExec: map[string][]string{"mac": []string{"a.sh"}, "linux": []string{"b.sh"}}}
	linuxOnly := auditCommand{ID: "linux-only", Display: "Linux", OSExec: map[string][]string{"linux": []string{"b.sh"}}}
	macOnly := auditCommand{ID: "mac-only", Display: "Mac", OSExec: map[string][]string{"mac": []string{"a.sh"}}}

	tests := []struct {
		name       string
		commands   []auditCommand
		detectedOS string
		wantIDs    []string
	}{
		{
			name:       "mac sees mac-supported only",
			commands:   []auditCommand{macLinux, linuxOnly, macOnly},
			detectedOS: "mac",
			wantIDs:    []string{"both", "mac-only"},
		},
		{
			name:       "linux sees linux-supported only",
			commands:   []auditCommand{macLinux, linuxOnly, macOnly},
			detectedOS: "linux",
			wantIDs:    []string{"both", "linux-only"},
		},
		{
			name:       "empty list when no support",
			commands:   []auditCommand{macOnly, linuxOnly},
			detectedOS: "windows",
			wantIDs:    []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commandsForCurrentOS(tt.commands, tt.detectedOS)
			gotIDs := make([]string, len(got))
			for i := range got {
				gotIDs[i] = got[i].ID
			}
			if !sliceEqual(gotIDs, tt.wantIDs) {
				t.Errorf("commandsForCurrentOS() = %v, want %v", gotIDs, tt.wantIDs)
			}
		})
	}
}

func TestCommandExecForOS(t *testing.T) {
	tests := []struct {
		name       string
		cmd        auditCommand
		detectedOS string
		want       []string
		wantErr    string
	}{
		{
			name:       "run full resolves correctly on mac",
			cmd:        auditCommand{ID: "full", OSExec: map[string][]string{"mac": []string{"audit/mac/full-audit.sh"}, "linux": []string{"audit/linux/full-audit.sh"}}},
			detectedOS: "mac",
			want:       []string{"audit/mac/full-audit.sh"},
		},
		{
			name:       "missing current-OS exec fails cleanly",
			cmd:        auditCommand{ID: "full", OSExec: map[string][]string{"linux": []string{"audit/linux/full-audit.sh"}}},
			detectedOS: "mac",
			wantErr:    `command "full" is not available on "mac"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := commandExecForOS(tt.cmd, tt.detectedOS)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("commandExecForOS() = %v, want error containing %q", got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("commandExecForOS() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("commandExecForOS() error = %v", err)
			}
			if !sliceEqual(got, tt.want) {
				t.Errorf("commandExecForOS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadCommands(t *testing.T) {
	tmp := t.TempDir()
	cliDir := filepath.Join(tmp, "cli")
	if err := os.MkdirAll(cliDir, 0o755); err != nil {
		t.Fatal(err)
	}
	auditDir := filepath.Join(tmp, "audit", "mac")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(auditDir, "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	validManifest := `{"commands":[{"id":"mac-linux","display":"Mac/Linux","os_exec":{"mac":["audit/mac/script.sh"],"linux":["audit/mac/script.sh"]}},{"id":"linux-only","display":"Linux","os_exec":{"linux":["audit/mac/script.sh"]}}]}`

	tests := []struct {
		name         string
		manifestPath string
		detectedOS   string
		wantCount    int
		wantErr      bool
		wantErrMsg   string
		setup        func() // optional setup, e.g. write manifest
	}{
		{
			name:         "filtering by OS mac",
			manifestPath: filepath.Join(cliDir, "commands.json"),
			detectedOS:   "mac", // kept for table compatibility; loadCommands no longer filters
			wantCount:    2,
			setup:        func() { os.WriteFile(filepath.Join(tmp, "cli", "commands.json"), []byte(validManifest), 0o644) },
		},
		{
			name:         "filtering by OS linux",
			manifestPath: filepath.Join(cliDir, "commands.json"),
			detectedOS:   "linux", // kept for table compatibility; loadCommands no longer filters
			wantCount:    2,
			setup:        func() { os.WriteFile(filepath.Join(tmp, "cli", "commands.json"), []byte(validManifest), 0o644) },
		},
		{
			name:         "missing file",
			manifestPath: filepath.Join(tmp, "cli", "nonexistent.json"),
			detectedOS:   "mac",
			wantErr:      true,
			wantErrMsg:   "manifest not found",
		},
		{
			name:         "malformed JSON",
			manifestPath: filepath.Join(cliDir, "commands.json"),
			detectedOS:   "mac",
			wantErr:      true,
			wantErrMsg:   "failed to parse manifest",
			setup:        func() { os.WriteFile(filepath.Join(tmp, "cli", "commands.json"), []byte("{invalid}"), 0o644) },
		},
		{
			name:         "empty os_exec {} fails load validation",
			manifestPath: filepath.Join(cliDir, "commands.json"),
			detectedOS:   "mac",
			wantErr:      true,
			wantErrMsg:   "os_exec must contain at least one target",
			setup:        func() { os.WriteFile(filepath.Join(tmp, "cli", "commands.json"), []byte(`{"commands":[{"id":"x","display":"X","os_exec":{}}]}`), 0o644) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			cmds, err := loadCommands(tt.manifestPath)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("loadCommands() = %d commands, nil; want error containing %q", len(cmds), tt.wantErrMsg)
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("loadCommands() error = %v, want containing %q", err, tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("loadCommands() = %v", err)
				return
			}
			if len(cmds) != tt.wantCount {
				t.Errorf("loadCommands() returned %d commands, want %d", len(cmds), tt.wantCount)
			}
		})
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestResolveRepoRoot_FallbackToExtraction(t *testing.T) {
	// When no on-disk repo root exists (e.g. standalone binary), resolveRepoRoot
	// falls back to extracting embedded files. This test verifies that path.
	// Note: This test may use extraction when run via "go test" because the
	// test binary lives in the build cache, not the repo.
	origRoot := os.Getenv("OSAUDIT_ROOT")
	os.Unsetenv("OSAUDIT_ROOT")
	defer func() {
		if origRoot != "" {
			os.Setenv("OSAUDIT_ROOT", origRoot)
		}
	}()

	root, err := resolveRepoRoot()
	if err != nil {
		t.Fatalf("resolveRepoRoot() = %v", err)
	}
	manifestPath := filepath.Join(root, "cli", "commands.json")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("manifest at %s: %v", manifestPath, err)
	}
	// Verify audit script exists
	auditScript := filepath.Join(root, "audit", "mac", "full-audit.sh")
	if _, err := os.Stat(auditScript); err != nil {
		t.Errorf("audit script at %s: %v", auditScript, err)
	}
	// Verify Python helpers exist
	probePy := filepath.Join(root, "core", "probe_failures_summary.py")
	if _, err := os.Stat(probePy); err != nil {
		t.Errorf("probe_failures_summary.py at %s: %v", probePy, err)
	}
	// Clean up if we used extraction (extractedCleanup was set)
	if extractedCleanup != nil {
		extractedCleanup()
		extractedCleanup = nil
	}
}

// TestRunPrintRunMeta outputs valid JSON on stdout and logs on stderr.
func TestRunPrintRunMeta(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("audit scripts only exist for linux/mac")
	}
	// Use module root (where go.mod lives) so dist/osaudit is found when built from repo
	cwd, _ := os.Getwd()
	for d := cwd; d != ""; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			cwd = d
			break
		}
	}
	root := cwd
	bin := buildOSAuditBinary(t, root)

	cmd := exec.Command(bin, "run", "execution", "--print-run-meta", "--", "--ndjson", "--redact-all")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "OSAUDIT_ROOT="+root)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Fatalf("run failed: %v\nstderr: %s", err, stderr.String())
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		t.Fatal("stdout empty; expected JSON")
	}
	if stderr.Len() == 0 {
		t.Error("stderr empty; expected logs")
	}

	var meta struct {
		RunID     string `json:"run_id"`
		CreatedAt string `json:"created_at"`
		Platform  string `json:"platform"`
		AuditID   string `json:"audit_id"`
		Dir       string `json:"dir"`
		NDJSON    string `json:"ndjson"`
		Report    string `json:"report"`
	}
	if err := json.Unmarshal([]byte(out), &meta); err != nil {
		t.Fatalf("stdout not valid JSON: %v\nraw: %s", err, out)
	}
	if meta.AuditID != "execution" {
		t.Errorf("audit_id = %q, want execution", meta.AuditID)
	}
	if meta.Platform != "linux" && meta.Platform != "mac" {
		t.Errorf("platform = %q, want linux or mac", meta.Platform)
	}
	// dir should be timestamped: output/execution-audit/YYYYMMDD-HHMMSS
	if !strings.Contains(meta.Dir, "output/execution-audit/") {
		t.Errorf("dir = %q, want output/execution-audit/<timestamp>", meta.Dir)
	}
}

// TestListAndRun_UnsupportedOS verifies: list shows only supported commands;
// run of a command with no current-OS exec fails with a clear error.
func TestListAndRun_UnsupportedOS(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("audit scripts only exist for linux/mac")
	}
	cwd, _ := os.Getwd()
	for d := cwd; d != ""; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			cwd = d
			break
		}
	}
	bin := buildOSAuditBinary(t, cwd)

	tmp := t.TempDir()
	cliDir := filepath.Join(tmp, "cli")
	os.MkdirAll(cliDir, 0o755)
	auditDir := filepath.Join(tmp, "audit", "mac")
	os.MkdirAll(auditDir, 0o755)
	os.WriteFile(filepath.Join(auditDir, "script.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755)

	// Manifest: full (mac+linux), linux-only (linux only)
	manifest := `{"commands":[{"id":"full","display":"Full","os_exec":{"mac":["audit/mac/script.sh"],"linux":["audit/mac/script.sh"]}},{"id":"linux-only","display":"Linux only","os_exec":{"linux":["audit/mac/script.sh"]}}]}`
	os.WriteFile(filepath.Join(cliDir, "commands.json"), []byte(manifest), 0o644)

	osName := "mac"
	if runtime.GOOS == "linux" {
		osName = "linux"
	}

	// list: on mac, linux-only must not appear; on linux, both appear
	listCmd := exec.Command(bin, "list")
	listCmd.Dir = tmp
	listCmd.Env = append(os.Environ(), "OSAUDIT_ROOT="+tmp)
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("osaudit list failed: %v\n%s", err, listOut)
	}
	listStr := string(listOut)
	if osName == "mac" && strings.Contains(listStr, "linux-only") {
		t.Errorf("list on mac should not show linux-only command, got:\n%s", listStr)
	}

	// run linux-only on mac: must fail with clear error
	if osName == "mac" {
		runCmd := exec.Command(bin, "run", "linux-only")
		runCmd.Dir = tmp
		runCmd.Env = append(os.Environ(), "OSAUDIT_ROOT="+tmp)
		var stderr strings.Builder
		runCmd.Stderr = &stderr
		_ = runCmd.Run()
		errStr := stderr.String()
		if !strings.Contains(errStr, `command "linux-only" is not available on "mac"`) {
			t.Errorf("run linux-only on mac should fail with clear error, got stderr:\n%s", errStr)
		}
	}
}

// TestRunPrintRunMeta_NoJSONOnFailure verifies no JSON is printed when script fails.
func TestRunPrintRunMeta_NoJSONOnFailure(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("audit scripts only exist for linux/mac")
	}
	cwd, _ := os.Getwd()
	for d := cwd; d != ""; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			cwd = d
			break
		}
	}
	bin := buildOSAuditBinary(t, cwd)

	// Use unknown command id so run fails before script executes
	cmd := exec.Command(bin, "run", "nonexistent-id", "--print-run-meta", "--", "--ndjson")
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "OSAUDIT_ROOT="+cwd)
	var stdout strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	_ = cmd.Run() // expect non-zero exit

	out := strings.TrimSpace(stdout.String())
	if out != "" {
		t.Errorf("stdout should be empty on failure, got: %s", out)
	}
}

func buildOSAuditBinary(t *testing.T, root string) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "osaudit-test-bin")
	build := exec.Command("go", "build", "-o", bin, "./cmd/osaudit")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build osaudit binary: %v\n%s", err, string(out))
	}
	return bin
}
