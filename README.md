# Operating System Audit

A cross-platform audit tool for inspecting the observable state of an operating system.

This project provides structured, conservative (read-only) audit capabilities for macOS, Linux, and Windows. It is designed to help users understand disk usage, system artifacts, persistence surfaces, and environment state without modifying the system.

The tool produces both human-readable reports and machine-readable telemetry suitable for automation, comparison, and ingestion into monitoring systems.

---

## Design Principles

**Read-only by default**  
No audit operation deletes, modifies, or moves files.

**Deterministic output**  
Reports are stable and suitable for comparison over time.

**Structured telemetry**  
Machine-readable NDJSON output enables downstream analysis and normalization.

**Cross-platform architecture**  
Audit collectors are implemented per-OS, with a unified interface layer.

**Separation of concerns**

- `audit/` → collectors (OS-specific)
- `cli/` → execution interface
- `cmd/osaudit/` → compiled user-facing binary
- `core/` → normalization and schema logic
- `output/` → generated reports

---

## Current Capabilities

### macOS

Home cleanup audit:

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
./dist/osaudit run cleanup -- --ndjson
```

Command manifest shape is documented in `cli/commands.schema.json` for editor/CI validation.
