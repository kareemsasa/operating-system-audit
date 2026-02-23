# Operating System Audit

An audit tool for inspecting the observable state of an operating system. The CLI and manifest format are designed for cross-platform use; collectors are implemented per-OS.

This project provides structured, conservative (read-only) audit capabilities. It is designed to help users understand disk usage, system artifacts, persistence surfaces, and environment state without modifying the system.

The tool produces both human-readable reports and machine-readable telemetry suitable for automation, comparison, and ingestion into monitoring systems.

---

## Platform Support

| Platform | Status   |
|----------|----------|
| macOS    | Full     |
| Linux    | Planned  |
| Windows  | Planned  |

---

## Design Principles

**Read-only by default**  
No audit operation deletes, modifies, or moves files.

**Deterministic output**  
Reports are stable and suitable for comparison over time.

**Structured telemetry**  
Machine-readable NDJSON output enables downstream analysis and normalization.

**Per-OS collectors**  
Audit collectors are implemented per-OS, with a unified interface layer.

**Separation of concerns**

- `audit/` → collectors (OS-specific)
- `cli/` → execution interface
- `cmd/osaudit/` → compiled user-facing binary
- `core/` → visualization helpers (e.g. heatmap rendering)
- `output/` → generated reports

---

## Current Capabilities

### macOS

Full system audit:

- Disk usage overview
- Large file detection
- Installer artifact detection (.dmg, .pkg, .zip)
- Trash size analysis
- Broken symlink detection
- Node modules and Git repository footprint
- Windows artifact detection (Thumbs.db, desktop.ini)
- Metadata and system identification

Outputs:

- Markdown report
- Optional NDJSON structured telemetry

---

## Installation

### From release (macOS/Linux)

Download the latest binary for your OS and architecture:

```bash
# Detect OS and arch (matches goreleaser: darwin/linux, amd64/arm64)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
[ "$ARCH" = "x86_64" ] && ARCH=amd64
[ "$ARCH" = "aarch64" ] && ARCH=arm64
curl -sSL "https://github.com/kareemsasa/operating-system-audit/releases/latest/download/osaudit_${OS}_${ARCH}.tar.gz" | tar xz -C /usr/local/bin osaudit
chmod +x /usr/local/bin/osaudit
```

### From source (Go)

```bash
go install github.com/kareemsasa/operating-system-audit/cmd/osaudit@latest
```

### Build from repo

Clone the repository:

```bash
git clone https://github.com/kareemsasa/operating-system-audit.git
cd operating-system-audit
```

Build the CLI:

```bash
go build -o dist/osaudit ./cmd/osaudit
```

Run interactively:

```bash
./dist/osaudit
```

List available commands for the detected OS:

```bash
./dist/osaudit list
```

Run a command with pass-through flags:

```bash
./dist/osaudit run full -- --ndjson
```

Command manifest shape is documented in `cli/commands.schema.json` for editor/CI validation.

## CI

GitHub Actions runs a fast CI workflow on pushes and pull requests.
It verifies `go build` for `cmd/osaudit`, checks Bash script syntax, and runs lightweight CLI smoke tests (`list` and `--help`) without deep scans.
