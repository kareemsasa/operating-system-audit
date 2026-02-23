#!/usr/bin/env python3
"""
Test probe_failures_summary diff formatting.
Uses synthetic NDJSON fixtures to assert: tight burst, span+rate, (0.0/s) guard, mixed exit codes.
Also tests message redaction rules (order: HOME_DIR, CURRENT_USER, /Users/username/, ANSI strip).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE = REPO_ROOT / "tests" / "fixtures" / "probe_diff_baseline.ndjson"
CURRENT = REPO_ROOT / "tests" / "fixtures" / "probe_diff_current.ndjson"
DIFF_PY = REPO_ROOT / "core" / "diff.py"


def run_diff():
    result = subprocess.run(
        [sys.executable, str(DIFF_PY), "--baseline", str(BASELINE), "--current", str(CURRENT)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    return result.returncode, result.stdout, result.stderr


def test_probe_diff_formatting():
    code, out, err = run_diff()
    assert code == 2, f"diff with changes must exit 2, got {code}: {err}"
    assert "## Probe failures delta" in out

    # Tight burst: count>1, duration_ms=0
    assert "tight burst" in out, "Expected 'tight burst' for network.ifconfig_iface (5×, duration_ms=0)"

    # Span + rate: duration>=1s, rate shown
    assert "(5.71/s)" in out or "5.71" in out, "Expected rate for network.ifconfig_list (12× over 2.1s)"

    # (0.0/s) guard: sub-second duration should NOT show rate
    assert "(0.0/s)" not in out, "Should not show (0.0/s) for sub-second duration"

    # Mixed exit codes
    assert "(mixed)" in out, "Expected (mixed) for config.fdesetup_status with {1,255}"

    # Expected
    assert "(expected)" in out, "Expected (expected) for identity.dscl_list_users"

    # Topic grouping: identity probe under Identity, not Network
    assert "### Identity" in out
    assert "identity.dscl_list_users" in out
    # Ensure identity probe is under Identity section (lines between ### Identity and next ###)
    lines = out.split("\n")
    in_identity = False
    identity_probes = []
    for line in lines:
        if line.strip() == "### Identity":
            in_identity = True
            continue
        if in_identity:
            if line.startswith("###"):
                break
            if "identity." in line:
                identity_probes.append(line)
    assert any("identity.dscl_list_users" in p for p in identity_probes), \
        "identity.dscl_list_users should be under ### Identity"

    print("All probe diff formatting assertions passed.")


def test_no_op_change_not_emitted():
    """Probe with identical count, exit_codes, span, expected_state must NOT emit ~ Changed."""
    import tempfile
    meta = {"type": "meta", "run_id": "x", "timestamp": "2026-02-22T10:00:00Z"}
    # Identical probe in both: count 22, exit_codes {1:22}, same timestamps
    item = {
        "probe": "config.defaults_firewall_globalstate",
        "count": 22,
        "first_ts_ms": 1708600000000,
        "last_ts_ms": 1708600000000,
        "duration_ms": 0,
        "failure_rate": 22.0,
        "exit_codes": {"1": 22},
    }
    base_pf = {"type": "probe_failures_summary", "run_id": "base", "items": [item]}
    curr_pf = {"type": "probe_failures_summary", "run_id": "curr", "items": [item.copy()]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ndjson", delete=False) as f1:
        for row in [meta, base_pf]:
            f1.write(json.dumps(row) + "\n")
        base_path = f1.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ndjson", delete=False) as f2:
        for row in [meta, curr_pf]:
            f2.write(json.dumps(row) + "\n")
        curr_path = f2.name
    try:
        result = subprocess.run(
            [sys.executable, str(DIFF_PY), "--baseline", base_path, "--current", curr_path],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, "diff with no changes must exit 0"
        # Must NOT show ~ Changed for config.defaults_firewall_globalstate
        assert "~ config.defaults_firewall_globalstate" not in result.stdout, (
            "No-op change (22×→22×, same exit_codes) must not emit ~ Changed"
        )
        # Should report no changes
        assert "No changes detected" in result.stdout
    finally:
        import os
        os.unlink(base_path)
        os.unlink(curr_path)


def test_diff_exit_codes():
    """Exit 0 = no changes, 2 = changes detected, 1 = error (diff convention)."""
    result = subprocess.run(
        [sys.executable, str(DIFF_PY), "--baseline", str(BASELINE), "--current", str(CURRENT)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 2, "fixtures have changes → exit 2"

    result = subprocess.run(
        [sys.executable, str(DIFF_PY), "--baseline", "/nonexistent.ndjson", "--current", str(CURRENT)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 1, "missing file → exit 1"


def redact_stderr_message(msg, home_dir, current_user):
    """Mirror of _soft_capture_stderr_msg. Order: HOME_DIR, CURRENT_USER, /Users/ (if still present), ANSI."""
    if not msg:
        return ""
    msg = msg[:200]
    if home_dir:
        msg = msg.replace(home_dir, "~")
    if current_user:
        msg = msg.replace(f"/{current_user}/", "/<user>/")
    # Only run generic /Users/.../ if string still contains /Users/ (avoid double-sanitizing /<user>/)
    if "/Users/" in msg:
        msg = re.sub(r"/Users/[^/]+/", "/<user>/", msg)
    # Strip ANSI: SGR, CSI, OSC (BEL- or ST-terminated)
    msg = re.sub(r"\x1b\[[0-9;]*m", "", msg)
    msg = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", msg)
    msg = re.sub(r"\x1b\][^\x07]*\x07", "", msg)
    msg = re.sub(r"\x1b\][^\x1b]*\x1b\\\\", "", msg)
    return msg


def test_message_redaction_order():
    """Redaction order: HOME_DIR first, then CURRENT_USER, then generic /Users/username/."""
    home = "/Users/jane"
    user = "jane"
    # Path under HOME_DIR should become ~
    assert redact_stderr_message(f"Error: {home}/.config", home, user) == "Error: ~/.config"
    # Path /Users/jane/foo: HOME_DIR replaces /Users/jane -> ~, so ~/foo
    assert redact_stderr_message("Path /Users/jane/foo", home, user) == "Path ~/foo"
    # Network home: /Users/otheruser/ when current is jane - generic /Users/[^/]+/ redacts
    assert redact_stderr_message("Path /Users/otheruser/bar", home, user) == "Path /<user>/bar"
    # ANSI strip (SGR)
    assert redact_stderr_message("\x1b[31mError\x1b[0m", home, user) == "Error"
    # OSC strip (BEL-terminated)
    assert redact_stderr_message("\x1b]0;title\x07hello", home, user) == "hello"
    # /<user>/ not double-sanitized when /Users/ already redacted
    assert redact_stderr_message("Path /<user>/foo", home, user) == "Path /<user>/foo"
    print("Message redaction assertions passed.")


if __name__ == "__main__":
    test_message_redaction_order()
    test_probe_diff_formatting()
