# osaudit

Know when your system changes.

`osaudit` takes a read-only snapshot of your operating system — security config, network state, persistence surfaces, identity, running processes, and disk usage — then diffs snapshots over time to show exactly what changed.

```bash
# Take a snapshot
osaudit run full -- --ndjson

# A week later, take another and diff
osaudit run full -- --ndjson
osaudit diff --baseline old.ndjson --current new.ndjson
```

```
## Probe failures delta

### Security
  + config.fdesetup_status failed 2× (tight burst), exit_codes: {1:1,255:1} (mixed)

### Network
  + network.ifconfig_iface failed 5× (tight burst), exit_codes: {1:5}
  + network.ifconfig_list failed 12× (2024-02-22 11:11:41 → 2024-02-22 11:11:43 (5.71/s)), exit_codes: {1:12}

### Identity
  ~ identity.dscl_list_users 1×→3×, exit_codes: 70:+2 (expected)
```

Exit code 0 means nothing changed. Exit code 2 means something did.

## Install

**Binary (macOS/Linux):**

```bash
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
[ "$ARCH" = "x86_64" ] && ARCH=amd64
[ "$ARCH" = "aarch64" ] && ARCH=arm64
curl -sSL "https://github.com/kareemsasa/operating-system-audit/releases/latest/download/osaudit_${OS}_${ARCH}.tar.gz" \
  | tar xz -C /usr/local/bin osaudit
```

**From source:**

```bash
go install github.com/kareemsasa/operating-system-audit/cmd/osaudit@latest
```

## What it audits

| Module          | macOS probes                                                                                                         |
| --------------- | -------------------------------------------------------------------------------------------------------------------- |
| **Storage**     | Disk usage, large files, installers (.dmg/.pkg/.zip), trash, node_modules, git repos, broken symlinks, duplicates    |
| **Network**     | Interfaces, listening ports, DNS, firewall status, stealth mode, active connections, Wi-Fi                           |
| **Identity**    | Local users, admin group membership, sudo capability, SSH keys, authorized_keys, shell validation                    |
| **Config**      | FileVault, SIP, Gatekeeper, firewall, remote login, screen lock, auto-updates, Homebrew, shell profiles, environment |
| **Execution**   | Top processes (CPU/mem), cron jobs, LaunchAgents, login items, launchctl daemons                                     |
| **Persistence** | LaunchDaemons, LaunchAgents (system + user), kernel extensions, system extensions, login hooks, auth plugins         |

## Usage

```bash
# Interactive menu
osaudit

# List available commands
osaudit list

# Run a specific audit
osaudit run full -- --ndjson
osaudit run network
osaudit run config
osaudit run storage -- --deep --ndjson

# Diff two snapshots
osaudit diff --baseline baseline.ndjson --current current.ndjson
osaudit diff --baseline baseline.ndjson --current current.ndjson --ndjson
```

Every audit produces a Markdown report. Pass `--ndjson` to also get machine-readable output for diffing and automation.

## Platform support

| Platform | Status    |
| -------- | --------- |
| macOS    | Supported |
| Linux    | Planned   |
| Windows  | Planned   |

## Design

Read-only — nothing is deleted, modified, or moved. Reports are deterministic and suitable for comparison. The binary is self-contained (all scripts are embedded via `go:embed`).

Architecture: Go CLI dispatches to per-OS Bash collectors. The diff engine and subcommand routing are pure Go.

## License

[MIT](LICENSE)
