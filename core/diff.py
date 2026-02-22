#!/usr/bin/env python3
"""
Diff two NDJSON audit files. Matches rows by type, compares values, emits only deltas.
"""
import argparse
import json
import os
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        description="Diff two NDJSON audit files and output a change report."
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


def main():
    args = parse_args()

    baseline_rows = read_ndjson(args.baseline)
    current_rows = read_ndjson(args.current)

    base_by_type = group_by_type(baseline_rows)
    curr_by_type = group_by_type(current_rows)

    has_deltas = False

    # --- Storage delta (summary) ---
    base_sum = base_by_type.get("summary")
    curr_sum = curr_by_type.get("summary")
    storage_fields = ["home_bytes", "downloads_bytes", "desktop_bytes", "trash_bytes"]
    if base_sum and curr_sum:
        storage_deltas = []
        for field in storage_fields:
            b = base_sum.get(field)
            c = curr_sum.get(field)
            if b is not None and c is not None:
                delta = c - b
                if delta != 0:
                    pct = (delta / b * 100) if b else 0
                    storage_deltas.append(
                        (field, b, c, delta, pct)
                    )
        if storage_deltas:
            has_deltas = True
            if args.ndjson:
                for field, b, c, delta, pct in storage_deltas:
                    emit_diff_row(
                        "storage",
                        field=field,
                        baseline=b,
                        current=c,
                        delta=delta,
                        pct_change=round(pct, 2),
                    )
            else:
                print("## Storage delta")
                for field, b, c, delta, pct in storage_deltas:
                    sign = "+" if delta >= 0 else ""
                    print(
                        "  {0}: {1} → {2} ({3}{4}, {5:+.1f}%)".format(
                            field.replace("_bytes", ""),
                            fmt_bytes(b),
                            fmt_bytes(c),
                            sign,
                            fmt_bytes(delta),
                            pct,
                        )
                    )
                print()

    # --- Count changes (counts) ---
    base_counts = base_by_type.get("counts")
    curr_counts = curr_by_type.get("counts")
    count_fields = [
        "large_files",
        "node_modules",
        "broken_symlinks",
        "git_repos",
        "venv_cache",
    ]
    if base_counts and curr_counts:
        count_deltas = []
        for field in count_fields:
            b = base_counts.get(field)
            c = curr_counts.get(field)
            if b is not None and c is not None:
                delta = c - b
                if delta != 0:
                    count_deltas.append((field, b, c, delta))
        if count_deltas:
            has_deltas = True
            if args.ndjson:
                for field, b, c, delta in count_deltas:
                    emit_diff_row(
                        "count",
                        field=field,
                        baseline=b,
                        current=c,
                        delta=delta,
                    )
            else:
                print("## Count changes")
                for field, b, c, delta in count_deltas:
                    sign = "+" if delta >= 0 else ""
                    print("  {0}: {1} → {2} ({3}{4})".format(field, b, c, sign, delta))
                print()

    # --- Security config changes ---
    base_sec = base_by_type.get("security_config")
    curr_sec = curr_by_type.get("security_config")
    sec_fields = ["filevault", "sip", "gatekeeper", "firewall"]
    if base_sec and curr_sec:
        sec_changes = []
        for field in sec_fields:
            b = base_sec.get(field)
            c = curr_sec.get(field)
            if b is not None and c is not None and b != c:
                sec_changes.append((field, b, c))
        if sec_changes:
            has_deltas = True
            if args.ndjson:
                for field, b, c in sec_changes:
                    emit_diff_row(
                        "security_config",
                        field=field,
                        baseline=b,
                        current=c,
                    )
            else:
                print("## Security config changes")
                for field, b, c in sec_changes:
                    b_str = "on" if b else "off"
                    c_str = "on" if c else "off"
                    print("  {0}: {1} → {2}".format(field, b_str, c_str))
                print()

    # --- Homebrew delta ---
    base_brew = base_by_type.get("homebrew_summary")
    curr_brew = curr_by_type.get("homebrew_summary")
    if base_brew and curr_brew:
        brew_deltas = []
        for field in ("formulae", "casks"):
            b = base_brew.get(field)
            c = curr_brew.get(field)
            if b is not None and c is not None:
                delta = c - b
                if delta != 0:
                    brew_deltas.append((field, b, c, delta))
        if brew_deltas:
            has_deltas = True
            if args.ndjson:
                for field, b, c, delta in brew_deltas:
                    emit_diff_row(
                        "homebrew",
                        field=field,
                        baseline=b,
                        current=c,
                        delta=delta,
                    )
            else:
                print("## Homebrew delta")
                for field, b, c, delta in brew_deltas:
                    sign = "+" if delta >= 0 else ""
                    print(
                        "  {0}: {1} → {2} ({3}{4})".format(field, b, c, sign, delta)
                    )
                print()

    # --- New warnings ---
    base_warn_codes = collect_warning_codes(baseline_rows)
    curr_warn_codes = collect_warning_codes(current_rows)
    new_warnings = curr_warn_codes - base_warn_codes
    if new_warnings:
        has_deltas = True
        if args.ndjson:
            emit_diff_row("new_warnings", codes=sorted(new_warnings))
        else:
            print("## New warnings")
            for code in sorted(new_warnings):
                print("  - {0}".format(code))
            print()

    if not has_deltas and not args.ndjson:
        print("No changes detected between baseline and current.")
    elif not has_deltas and args.ndjson:
        pass  # No diff rows emitted


if __name__ == "__main__":
    main()
