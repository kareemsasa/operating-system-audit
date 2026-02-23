#!/usr/bin/env python3
"""
Diff two NDJSON audit files. Matches rows by type, compares values, emits only deltas.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

SPAN_SINGLE_SHOT = "single-shot"
SPAN_TIGHT_BURST = "tight burst"

# Severity: prefix patterns first (data-driven), then exact overrides.
# config.* = security-critical, identity.dscl_* / network.ifconfig_* = load-bearing, etc.
PROBE_SEVERITY_PREFIX = [
    ("config.", "high"),
    ("network.defaults_", "high"),
    ("network.socketfilterfw_", "high"),
    ("identity.dscl_", "medium"),
    ("identity.dseditgroup_", "medium"),
    ("network.ifconfig_", "medium"),
    ("network.lsof_", "medium"),
    ("network.scutil_", "medium"),
    ("execution.launchctl_", "medium"),
    ("execution.ps_", "low"),
    ("persistence.", "medium"),
]
PROBE_SEVERITY_EXACT = {
    "network.socketfilterfw_stealth": "high",
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Probes that commonly fail with these codes in non-interactive contexts (permission, TCC, etc).
# When all exit_codes match expected, severity can be downgraded for display.
PROBE_EXPECTED_EXIT_CODES = {
    "config.fdesetup_status": {15, 1},  # permission denied, etc
    "config.defaults_firewall_globalstate": {1},
    "config.defaults_screen_lock_delay": {1},
    "network.defaults_firewall_globalstate": {1},
    "identity.dscl_list_users": {70, 1},  # internal software error, permission
    "identity.dseditgroup_checkmember": {1},
}

# Topic for grouping (probe prefix -> display name). Order = display priority.
PROBE_TOPIC = {
    "config.": "Security",
    "network.": "Network",
    "identity.": "Identity",
    "storage.": "Storage",
    "execution.": "Execution",
    "persistence.": "Persistence",
}
TOPIC_ORDER = ["Security", "Network", "Identity", "Storage", "Execution", "Persistence", "Other"]


def probe_severity(probe):
    if probe in PROBE_SEVERITY_EXACT:
        return PROBE_SEVERITY_EXACT[probe]
    for prefix, sev in PROBE_SEVERITY_PREFIX:
        if probe.startswith(prefix):
            return sev
    return "low"


def probe_expected_exit_codes(probe):
    return PROBE_EXPECTED_EXIT_CODES.get(probe, set())


def probe_failure_expected_state(probe, exit_codes):
    """Returns 'expected' | 'mixed' | 'unexpected'. Mixed = some match, some don't (regression hiding in noise)."""
    expected = probe_expected_exit_codes(probe)
    if not expected:
        return "unexpected"
    codes = {int(c) for c in (exit_codes or {}).keys()}
    if not codes:
        return "unexpected"
    if codes <= expected:
        return "expected"
    if codes & expected:
        return "mixed"
    return "unexpected"


def probe_failure_is_expected(probe, exit_codes):
    """True only when all exit codes match expected. Mixed/unexpected = False."""
    return probe_failure_expected_state(probe, exit_codes) == "expected"


def probe_failure_expected_suffix(probe, exit_codes):
    """Display suffix: (expected) | (mixed) | empty."""
    state = probe_failure_expected_state(probe, exit_codes)
    if state == "expected":
        return " (expected)"
    if state == "mixed":
        return " (mixed)"
    return ""


def probe_topic(probe):
    """Derive topic from probe prefix. Falls back to Other only if unclassifiable."""
    for prefix, topic in PROBE_TOPIC.items():
        if probe.startswith(prefix):
            return topic
    return "Other"


def probe_failure_span_label(count, dur_ms):
    """Single rule for span display: single-shot | tight burst | span + rate."""
    if count == 1:
        return SPAN_SINGLE_SHOT
    if dur_ms is None or dur_ms == 0:
        return SPAN_TIGHT_BURST
    return "span"


def probe_failure_span_fmt(count, dur_ms, rate, first_ts, last_ts, fmt_ts_fn):
    """Format span for display. Avoids (0.0/s) when duration rounds weirdly."""
    label = probe_failure_span_label(count, dur_ms)
    if label == SPAN_SINGLE_SHOT:
        return SPAN_SINGLE_SHOT
    if label == SPAN_TIGHT_BURST:
        return SPAN_TIGHT_BURST
    span = "{0} → {1}".format(fmt_ts_fn(first_ts), fmt_ts_fn(last_ts))
    dur_sec = (dur_ms or 0) / 1000.0
    if dur_sec >= 1 and rate and rate > 0:
        return "{0} ({1:.2f}/s)".format(span, rate)
    return span


def exit_codes_delta(base_ec, curr_ec):
    """Compute delta map: treat missing as 0. Returns dict of code -> delta."""
    all_codes = {c for ec in (base_ec or {}, curr_ec or {}) for c in ec}
    return {str(c): (curr_ec.get(c, 0) or 0) - (base_ec.get(c, 0) or 0) for c in all_codes}


def fmt_ts_ms(ts_ms):
    """Convert ms timestamp to ISO-like string for display."""
    if ts_ms is None or ts_ms == 0:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError):
        return str(ts_ms)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Diff two NDJSON audit files and output a change report.",
        epilog="Exit codes: 0 = no changes, 2 = changes detected, 1 = error.",
    )
    parser.add_argument("--baseline", required=True, help="Path to baseline NDJSON file")
    parser.add_argument("--current", required=True, help="Path to current NDJSON file")
    parser.add_argument(
        "--ndjson",
        action="store_true",
        help="Emit structured diff rows as NDJSON instead of human-readable summary",
    )
    return parser.parse_args()


def die(message):
    print("Error: {0}".format(message), file=sys.stderr)
    sys.exit(1)


def read_ndjson(path):
    rows = []
    if not os.path.isfile(path):
        die("NDJSON file not found: {0}".format(path))

    with open(path, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                die(
                    "Invalid JSON at line {0}: {1}".format(
                        line_no, str(exc).splitlines()[0]
                    )
                )
            if not isinstance(obj, dict):
                die("NDJSON row {0} is not a JSON object".format(line_no))
            rows.append(obj)
    return rows


def group_by_type(rows):
    """Group rows by type. For types with multiple rows, keep the last one (most complete)."""
    by_type = {}
    for row in rows:
        t = row.get("type")
        if t:
            by_type[t] = row
    return by_type


def collect_warning_codes(rows):
    """Collect unique warning identifiers from all warning rows."""
    codes = set()
    for row in rows:
        if row.get("type") != "warning":
            continue
        if "code" in row:
            codes.add(row["code"])
        elif "soft_failures" in row:
            codes.add("soft_failures")
    return codes


def fmt_bytes(n):
    """Format bytes for display (e.g. 1.2G, 500M)."""
    if n is None:
        return "N/A"
    n = abs(n)
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return "{0}{1}".format(int(n) if unit == "B" else round(n, 1), unit)
        n /= 1024
    return "{0}P".format(round(n, 1))


def emit_diff_row(diff_type, **kwargs):
    """Emit a single diff row (for --ndjson mode)."""
    row = {"type": "diff", "diff_type": diff_type, **kwargs}
    print(json.dumps(row, ensure_ascii=False))


def _compute_storage_deltas(base_sum, curr_sum):
    storage_fields = ["home_bytes", "downloads_bytes", "desktop_bytes", "trash_bytes"]
    if not base_sum or not curr_sum:
        return []
    out = []
    for f in storage_fields:
        b, c = base_sum.get(f), curr_sum.get(f)
        if b is not None and c is not None:
            delta = c - b
            if delta != 0:
                pct = (delta / b * 100) if b else 0
                out.append((f, b, c, delta, pct))
    return out


def _print_storage_delta(deltas):
    print("## Storage delta")
    for field, b, c, delta, pct in deltas:
        sign = "+" if delta >= 0 else ""
        print("  {0}: {1} → {2} ({3}{4}, {5:+.1f}%)".format(
            field.replace("_bytes", ""), fmt_bytes(b), fmt_bytes(c), sign, fmt_bytes(delta), pct))
    print()


def _emit_storage_delta(base_sum, curr_sum, ndjson):
    deltas = _compute_storage_deltas(base_sum, curr_sum)
    if not deltas:
        return False
    if ndjson:
        for field, b, c, delta, pct in deltas:
            emit_diff_row("storage", field=field, baseline=b, current=c, delta=delta, pct_change=round(pct, 2))
    else:
        _print_storage_delta(deltas)
    return True


def _compute_count_deltas(base_counts, curr_counts):
    count_fields = ["large_files", "node_modules", "broken_symlinks", "git_repos", "venv_cache"]
    if not base_counts or not curr_counts:
        return []
    out = []
    for f in count_fields:
        b, c = base_counts.get(f), curr_counts.get(f)
        if b is not None and c is not None and c - b != 0:
            out.append((f, b, c, c - b))
    return out


def _print_count_delta(deltas):
    print("## Count changes")
    for field, b, c, delta in deltas:
        sign = "+" if delta >= 0 else ""
        print("  {0}: {1} → {2} ({3}{4})".format(field, b, c, sign, delta))
    print()


def _emit_count_delta(base_counts, curr_counts, ndjson):
    deltas = _compute_count_deltas(base_counts, curr_counts)
    if not deltas:
        return False
    if ndjson:
        for field, b, c, delta in deltas:
            emit_diff_row("count", field=field, baseline=b, current=c, delta=delta)
    else:
        _print_count_delta(deltas)
    return True


def _compute_security_changes(base_sec, curr_sec):
    sec_fields = ["filevault", "sip", "gatekeeper", "firewall"]
    if not base_sec or not curr_sec:
        return []
    out = []
    for f in sec_fields:
        b, c = base_sec.get(f), curr_sec.get(f)
        if b is not None and c is not None and b != c:
            out.append((f, b, c))
    return out


def _print_security_config_delta(changes):
    print("## Security config changes")
    for field, b, c in changes:
        print("  {0}: {1} → {2}".format(field, "on" if b else "off", "on" if c else "off"))
    print()


def _emit_security_config_delta(base_sec, curr_sec, ndjson):
    changes = _compute_security_changes(base_sec, curr_sec)
    if not changes:
        return False
    if ndjson:
        for field, b, c in changes:
            emit_diff_row("security_config", field=field, baseline=b, current=c)
    else:
        _print_security_config_delta(changes)
    return True


def _compute_homebrew_deltas(base_brew, curr_brew):
    if not base_brew or not curr_brew:
        return []
    out = []
    for f in ("formulae", "casks"):
        b, c = base_brew.get(f), curr_brew.get(f)
        if b is not None and c is not None and c - b != 0:
            out.append((f, b, c, c - b))
    return out


def _print_homebrew_delta(deltas):
    print("## Homebrew delta")
    for field, b, c, delta in deltas:
        sign = "+" if delta >= 0 else ""
        print("  {0}: {1} → {2} ({3}{4})".format(field, b, c, sign, delta))
    print()


def _emit_homebrew_delta(base_brew, curr_brew, ndjson):
    deltas = _compute_homebrew_deltas(base_brew, curr_brew)
    if not deltas:
        return False
    if ndjson:
        for field, b, c, delta in deltas:
            emit_diff_row("homebrew", field=field, baseline=b, current=c, delta=delta)
    else:
        _print_homebrew_delta(deltas)
    return True


def _emit_new_warnings(new_warnings, ndjson):
    if not new_warnings:
        return False
    if ndjson:
        emit_diff_row("new_warnings", codes=sorted(new_warnings))
    else:
        print("## New warnings")
        for code in sorted(new_warnings):
            print("  - {0}".format(code))
        print()
    return True


def _probe_sort_key(probe, status):
    sev = SEVERITY_ORDER.get(probe_severity(probe), 2)
    status_order = {"new": 0, "resolved": 1, "changed": 2}
    return (sev, status_order.get(status, 3), probe)


def _norm_exit_codes(ec):
    """Normalize keys so {"1":1} == {1:1} for comparison."""
    if not ec:
        return {}
    out = {}
    for k, v in ec.items():
        try:
            kk = int(k)
        except Exception:
            kk = k
        out[kk] = int(v)
    return dict(sorted(out.items(), key=lambda x: x[0]))


def _probe_failure_is_changed(probe, base_it, curr_it):
    """True only when stable fingerprint changed: count, exit_codes, or expected_state.
    Ignore first_ts_ms, last_ts_ms, duration_ms, failure_rate — these vary run-to-run
    even when the failure pattern is identical (e.g. 22 failures scattered across the run)."""
    if base_it is None or curr_it is None:
        return True

    if int(base_it.get("count", 0)) != int(curr_it.get("count", 0)):
        return True

    if _norm_exit_codes(base_it.get("exit_codes")) != _norm_exit_codes(curr_it.get("exit_codes")):
        return True

    base_ec = base_it.get("exit_codes") or {}
    curr_ec = curr_it.get("exit_codes") or {}
    if probe_failure_expected_state(probe, base_ec) != probe_failure_expected_state(probe, curr_ec):
        return True

    return False


def _build_probe_failure_entries(base_pf, curr_pf):
    base_probes = {it["probe"]: it for it in (base_pf.get("items") or [])} if base_pf else {}
    curr_probes = {it["probe"]: it for it in (curr_pf.get("items") or [])} if curr_pf else {}
    new_probes = set(curr_probes) - set(base_probes)
    resolved_probes = set(base_probes) - set(curr_probes)
    common = set(base_probes) & set(curr_probes)
    changed_probes = [
        p for p in common
        if _probe_failure_is_changed(p, base_probes[p], curr_probes[p])
    ]
    entries = []
    for p in sorted(new_probes, key=lambda x: _probe_sort_key(x, "new")):
        entries.append(("new", p, None, curr_probes[p]))
    for p in sorted(resolved_probes, key=lambda x: _probe_sort_key(x, "resolved")):
        entries.append(("resolved", p, base_probes[p], None))
    for p in sorted(changed_probes, key=lambda x: _probe_sort_key(x, "changed")):
        entries.append(("changed", p, base_probes[p], curr_probes[p]))
    return entries


def _emit_probe_failure_row(status, probe, base_it, curr_it):
    it = curr_it or base_it
    ec = it.get("exit_codes") if it else {}
    row = {
        "probe": probe,
        "status": status,
        "severity": probe_severity(probe),
        "topic": probe_topic(probe),
        "expected": probe_failure_is_expected(probe, ec),
        "expected_state": probe_failure_expected_state(probe, ec),
    }
    if status == "new":
        row["current"] = curr_it
    elif status == "resolved":
        row["baseline"] = base_it
    else:
        row["baseline"] = base_it
        row["current"] = curr_it
        ec_delta = exit_codes_delta(base_it.get("exit_codes"), curr_it.get("exit_codes"))
        row["exit_codes_delta"] = {k: v for k, v in ec_delta.items() if v != 0}
    emit_diff_row("probe_failure", **row)


def _format_probe_entry_new(probe, curr_it):
    c = curr_it.get("count", 0)
    ec = curr_it.get("exit_codes") or {}
    ec_str = ",".join("{0}:{1}".format(k, v) for k, v in sorted(ec.items(), key=lambda x: int(x[0])))
    span_str = probe_failure_span_fmt(
        c, curr_it.get("duration_ms", 0), curr_it.get("failure_rate", 0),
        curr_it.get("first_ts_ms"), curr_it.get("last_ts_ms"), fmt_ts_ms
    )
    exp_suffix = probe_failure_expected_suffix(probe, ec)
    return "  + {0} failed {1}× ({2}), exit_codes: {{{3}}}{4}".format(probe, c, span_str, ec_str, exp_suffix)


def _format_probe_entry_resolved(probe, base_it):
    c = base_it.get("count", 0)
    ec = base_it.get("exit_codes") or {}
    ec_str = ",".join("{0}:{1}".format(k, v) for k, v in sorted(ec.items(), key=lambda x: int(x[0])))
    exp_suffix = probe_failure_expected_suffix(probe, ec)
    return "  - {0} resolved (was {1}×, exit_codes: {{{2}}}){3}".format(probe, c, ec_str, exp_suffix)


def _format_probe_entry_changed(probe, base_it, curr_it):
    bc, cc = base_it.get("count", 0), curr_it.get("count", 0)
    ec_delta = exit_codes_delta(base_it.get("exit_codes"), curr_it.get("exit_codes"))
    delta_strs = [("{0}:{1:+d}".format(k, v)) for k, v in sorted(ec_delta.items(), key=lambda x: int(x[0])) if v != 0]
    exp_suffix = probe_failure_expected_suffix(probe, curr_it.get("exit_codes"))
    # Only show exit_codes fragment when histogram delta is non-empty
    if delta_strs:
        return "  ~ {0} {1}×→{2}×, exit_codes: {3}{4}".format(probe, bc, cc, ", ".join(delta_strs), exp_suffix)
    return "  ~ {0} {1}×→{2}×{3}".format(probe, bc, cc, exp_suffix)


def _emit_probe_failures_delta(base_pf, curr_pf, ndjson):
    entries = _build_probe_failure_entries(base_pf, curr_pf)
    if ndjson:
        if not entries:
            return False
        for status, probe, base_it, curr_it in entries:
            _emit_probe_failure_row(status, probe, base_it, curr_it)
        return True
    # Human-readable: always print section so user knows it ran
    print("## Probe failures delta")
    if not entries:
        print("  No changes detected")
    else:
        _print_probe_failures_delta_body(entries)
    print()
    return bool(entries)


def _print_probe_failures_delta_body(entries):
    """Print topic groups and items (caller prints header)."""
    by_topic = {}
    for status, probe, base_it, curr_it in entries:
        by_topic.setdefault(probe_topic(probe), []).append((status, probe, base_it, curr_it))
    for topic in sorted(by_topic.keys(), key=lambda t: (TOPIC_ORDER.index(t) if t in TOPIC_ORDER else 99, t)):
        items = by_topic[topic]
        print("\n### {0}".format(topic))
        for status, probe, base_it, curr_it in items:
            if status == "new":
                print(_format_probe_entry_new(probe, curr_it))
            elif status == "resolved":
                print(_format_probe_entry_resolved(probe, base_it))
            else:
                print(_format_probe_entry_changed(probe, base_it, curr_it))


def main():
    args = parse_args()
    baseline_rows = read_ndjson(args.baseline)
    current_rows = read_ndjson(args.current)
    base_by_type = group_by_type(baseline_rows)
    curr_by_type = group_by_type(current_rows)
    ndjson = args.ndjson

    has_deltas = False
    has_deltas |= _emit_storage_delta(base_by_type.get("summary"), curr_by_type.get("summary"), ndjson)
    has_deltas |= _emit_count_delta(base_by_type.get("counts"), curr_by_type.get("counts"), ndjson)
    has_deltas |= _emit_security_config_delta(
        base_by_type.get("security_config"), curr_by_type.get("security_config"), ndjson
    )
    has_deltas |= _emit_homebrew_delta(
        base_by_type.get("homebrew_summary"), curr_by_type.get("homebrew_summary"), ndjson
    )
    new_warnings = collect_warning_codes(current_rows) - collect_warning_codes(baseline_rows)
    has_deltas |= _emit_new_warnings(new_warnings, ndjson)
    has_deltas |= _emit_probe_failures_delta(
        base_by_type.get("probe_failures_summary"), curr_by_type.get("probe_failures_summary"), ndjson
    )

    if not has_deltas and not ndjson:
        print("No changes detected between baseline and current.")

    # Exit 0 = no changes, 2 = changes detected (diff convention), 1 = error (via die())
    sys.exit(0 if not has_deltas else 2)


if __name__ == "__main__":
    main()
