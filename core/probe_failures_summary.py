#!/usr/bin/env python3
"""
Read probe failures TSV (count_key, ts_ms, exit_code) and emit probe_failures_summary NDJSON.
Used by audit/mac/lib/common.sh emit_probe_failures_summary().
"""
import json
import os
import sys
from typing import Optional, Tuple


def _parse_tsv_line(line: str) -> Optional[Tuple[str, int, int]]:
    """Parse one TSV line; return (key, ts, code) or None if invalid."""
    line = line.strip()
    if not line:
        return None
    parts = line.split("\t", 2)
    if len(parts) < 3 or not parts[0]:
        return None
    try:
        ts = int(parts[1]) if parts[1] else 0
        code = int(parts[2]) if parts[2] else 0
        return (parts[0], ts, code)
    except ValueError:
        return None


def _build_item(probe: str, g: dict) -> dict:
    """Build one summary item from group stats."""
    first_ts, last_ts = g["first"], g["last"]
    dur_ms = last_ts - first_ts
    dur_sec = dur_ms / 1000.0
    denom = dur_sec if dur_sec > 1 else 1
    rate = g["count"] / denom
    ec = dict(sorted(g["codes"].items(), key=lambda x: int(x[0])))
    return {
        "probe": probe,
        "count": g["count"],
        "first_ts_ms": first_ts,
        "last_ts_ms": last_ts,
        "duration_ms": dur_ms,
        "failure_rate": round(rate, 4),
        "exit_codes": ec,
    }


def summarize(pf_path: str, run_id: str = "") -> str:
    """Read TSV, group by key, compute stats, return JSON line."""
    groups = {}
    with open(pf_path, "r") as f:
        for line in f:
            parsed = _parse_tsv_line(line)
            if not parsed:
                continue
            key, ts, code = parsed
            if key not in groups:
                groups[key] = {"count": 0, "first": ts, "last": ts, "codes": {}}
            g = groups[key]
            g["count"] += 1
            g["first"] = min(g["first"], ts)
            g["last"] = max(g["last"], ts)
            ck = str(code)
            g["codes"][ck] = g["codes"].get(ck, 0) + 1

    items = [_build_item(probe, groups[probe]) for probe in sorted(groups.keys())]
    return json.dumps({"type": "probe_failures_summary", "run_id": run_id, "items": items})


def main():
    run_id = os.environ.get("RUN_ID", "")
    if len(sys.argv) < 2:
        sys.exit(1)
    pf_path = sys.argv[1]
    print(summarize(pf_path, run_id))


if __name__ == "__main__":
    main()
