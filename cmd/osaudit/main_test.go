package main

import (
	"os"
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
		name    string
		repoRoot string
		m       manifest
		wantErr string
	}{
		{
			name:     "valid manifest",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "valid", OS: []string{"mac"}, Display: "Valid", Exec: []string{"audit/mac/script.sh"}},
				},
			},
		},
		{
			name:     "missing ID",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "", OS: []string{"mac"}, Display: "X", Exec: []string{"audit/mac/script.sh"}},
				},
			},
			wantErr: "id is required",
		},
		{
			name:     "duplicate ID",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "dup", OS: []string{"mac"}, Display: "A", Exec: []string{"audit/mac/script.sh"}},
					{ID: "dup", OS: []string{"mac"}, Display: "B", Exec: []string{"audit/mac/script.sh"}},
				},
			},
			wantErr: "duplicate id",
		},
		{
			name:     "invalid OS",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "x", OS: []string{"solaris"}, Display: "X", Exec: []string{"audit/mac/script.sh"}},
				},
			},
			wantErr: "unsupported value",
		},
		{
			name:     "missing exec",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "x", OS: []string{"mac"}, Display: "X", Exec: []string{}},
				},
			},
			wantErr: "exec must contain at least one value",
		},
		{
			name:     "non-existent exec path",
			repoRoot: tmp,
			m: manifest{
				Commands: []auditCommand{
					{ID: "x", OS: []string{"mac"}, Display: "X", Exec: []string{"audit/mac/nonexistent.sh"}},
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
		name       string
		args       []string
		wantID     string
		wantPass   []string
		wantErr    bool
		wantErrMsg string
	}{
		{"no args (error)", []string{}, "", nil, true, "missing command id"},
		{"id only", []string{"full"}, "full", nil, false, ""},
		{"id + -- + passthrough", []string{"full", "--", "-x", "y"}, "full", []string{"-x", "y"}, false, ""},
		{"id + extra without -- (error)", []string{"full", "extra"}, "", nil, true, "pass-through"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, pass, err := parseRunArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRunArgs() = %q, %v, nil; want error containing %q", id, pass, tt.wantErrMsg)
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
		})
	}
}

func TestDetectOS(t *testing.T) {
	got, err := detectOS()
	if err != nil {
		t.Fatalf("detectOS() = %v", err)
	}
	want := map[string]string{
		"darwin": "mac",
		"linux":  "linux",
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

func TestCommandSupportsOS(t *testing.T) {
	tests := []struct {
		name       string
		cmd        auditCommand
		detectedOS string
		want       bool
	}{
		{"match", auditCommand{OS: []string{"mac"}}, "mac", true},
		{"no match", auditCommand{OS: []string{"mac"}}, "linux", false},
		{"multi-OS entries", auditCommand{OS: []string{"mac", "linux"}}, "linux", true},
		{"multi-OS first", auditCommand{OS: []string{"mac", "linux"}}, "mac", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commandSupportsOS(tt.cmd, tt.detectedOS)
			if got != tt.want {
				t.Errorf("commandSupportsOS(%v, %q) = %v, want %v", tt.cmd, tt.detectedOS, got, tt.want)
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

	validManifest := `{"commands":[{"id":"mac-only","os":["mac"],"display":"Mac","exec":["audit/mac/script.sh"]},{"id":"linux-only","os":["linux"],"display":"Linux","exec":["audit/mac/script.sh"]}]}`

	tests := []struct {
		name        string
		manifestPath string
		detectedOS  string
		wantCount   int
		wantErr     bool
		wantErrMsg  string
		setup       func() // optional setup, e.g. write manifest
	}{
		{
			name:         "filtering by OS mac",
			manifestPath: filepath.Join(cliDir, "commands.json"),
			detectedOS:   "mac",
			wantCount:    1,
			setup:        func() { os.WriteFile(filepath.Join(tmp, "cli", "commands.json"), []byte(validManifest), 0o644) },
		},
		{
			name:         "filtering by OS linux",
			manifestPath: filepath.Join(cliDir, "commands.json"),
			detectedOS:   "linux",
			wantCount:    1,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			cmds, err := loadCommands(tt.manifestPath, tt.detectedOS)
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
