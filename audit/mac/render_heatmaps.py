#!/usr/bin/env python3
import argparse
import collections
import html
import json
import os
import sys
from datetime import datetime, timezone


def parse_args():
    parser = argparse.ArgumentParser(
        description="Render cleanup-audit heatmaps (HTML-only, stdlib-only)."
    )
    parser.add_argument("--ndjson", required=True, help="Path to NDJSON input file")
    parser.add_argument("--outdir", required=True, help="Directory for HTML output")
    parser.add_argument(
        "--render-topn",
        type=int,
        default=50,
        help="Maximum number of offenders/bars to render (default: 50)",
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
            if "run_id" not in obj:
                die("NDJSON row {0} missing required field 'run_id'".format(line_no))
            rows.append(obj)
    if not rows:
        die("NDJSON file has no data rows")
    return rows


def select_run(rows):
    counts = collections.Counter()
    for row in rows:
        run_id = row.get("run_id")
        counts[run_id] += 1

    if not counts:
        die("No run_id values found")

    selected_run_id = counts.most_common(1)[0][0]
    selected_rows = [row for row in rows if row.get("run_id") == selected_run_id]
    ignored_rows = len(rows) - len(selected_rows)

    note = ""
    if len(counts) > 1:
        note = (
            "Multiple run_ids detected; rendering most frequent run_id "
            "'{0}' ({1}/{2} rows). Ignored {3} row(s) from other run_id(s)."
        ).format(selected_run_id, len(selected_rows), len(rows), ignored_rows)
    return selected_run_id, selected_rows, note


def safe_run_id(run_id):
    text = str(run_id)
    out = []
    for ch in text:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    sanitized = "".join(out).strip("._")
    if not sanitized:
        return "run"
    return sanitized


def to_int(value, default=0):
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return default
    return default


def human_bytes(num):
    value = float(num)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    while value >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return "{0} {1}".format(int(value), units[idx])
    return "{0:.2f} {1}".format(value, units[idx])


def escape(value):
    return html.escape(str(value), quote=True)


def short_label(path, max_len=26):
    if not isinstance(path, str) or not path:
        return "(unknown)"
    cleaned = path.rstrip("/")
    label = os.path.basename(cleaned) or cleaned
    if len(label) <= max_len:
        return label
    return label[: max_len - 1] + "…"


def extract_path_bytes(obj):
    if not isinstance(obj, dict):
        return None
    path = obj.get("path")
    size = to_int(obj.get("bytes"), default=-1)
    if isinstance(path, str) and size >= 0:
        return path, size
    return None


def collect_treemap_items(rows):
    items = []
    for row in rows:
        top = extract_path_bytes(row)
        if top:
            items.append({"path": top[0], "bytes": top[1]})

        children = row.get("items")
        if not isinstance(children, list):
            continue
        for child in children:
            child_item = extract_path_bytes(child)
            if child_item:
                items.append({"path": child_item[0], "bytes": child_item[1]})

    merged = {}
    for item in items:
        key = item["path"]
        if key not in merged:
            merged[key] = 0
        merged[key] += item["bytes"]

    merged_items = [{"path": k, "bytes": v} for k, v in merged.items() if v > 0]
    merged_items.sort(key=lambda x: x["bytes"], reverse=True)
    return merged_items


def collect_timing_items(rows):
    items = []
    for row in rows:
        if row.get("type") != "timing":
            continue
        section = row.get("section")
        elapsed_ms = to_int(row.get("elapsed_ms"), default=-1)
        if isinstance(section, str) and elapsed_ms >= 0:
            items.append({"section": section, "elapsed_ms": elapsed_ms})
    items.sort(key=lambda x: x["elapsed_ms"], reverse=True)
    return items


def page_shell(title_text, run_id, generated_at, callout, body_html):
    callout_html = ""
    if callout:
        callout_html = '<div class="callout">{0}</div>'.format(escape(callout))

    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0f1220;
      --panel: #171a2b;
      --text: #e9ecf9;
      --muted: #a9b0d0;
      --accent: #7cc8ff;
      --warn: #ffd27a;
      --tile: #4a6ee0;
      --tile-2: #6f8cff;
      --bar: #7bc9ff;
      --border: #2a2f4c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 20px;
    }}
    h1 {{ margin: 0 0 8px; font-size: 1.4rem; }}
    .meta {{ color: var(--muted); margin-bottom: 12px; }}
    .callout {{
      border: 1px solid #5f4a1e;
      background: #3a2f18;
      color: #ffe6b3;
      padding: 10px 12px;
      border-radius: 8px;
      margin-bottom: 14px;
    }}
    .note {{
      border: 1px solid var(--border);
      background: #121528;
      color: var(--warn);
      padding: 10px 12px;
      border-radius: 8px;
      margin-bottom: 14px;
    }}
    .panel {{
      border: 1px solid var(--border);
      background: var(--panel);
      border-radius: 10px;
      padding: 14px;
    }}
    .muted {{ color: var(--muted); }}
    .empty {{
      padding: 16px;
      border: 1px dashed var(--border);
      border-radius: 8px;
      color: var(--muted);
    }}
    .treemap {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      min-height: 380px;
      align-content: flex-start;
    }}
    .tile {{
      border-radius: 8px;
      border: 1px solid #2f447f;
      background: linear-gradient(135deg, var(--tile), var(--tile-2));
      min-width: 120px;
      min-height: 68px;
      padding: 8px;
      color: white;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    .tile-label {{
      font-size: 0.82rem;
      line-height: 1.2;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .tile-meta {{
      font-size: 0.72rem;
      opacity: 0.95;
    }}
    .bars {{
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .bar-row {{
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      background: #101328;
    }}
    .bar-fill {{
      background: linear-gradient(90deg, #5ebcff, var(--bar));
      padding: 6px 10px;
      color: #00142b;
      font-size: 0.84rem;
      font-weight: 600;
      white-space: nowrap;
      min-width: 90px;
    }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <div class="meta">Run ID: <code>{run_id}</code> | Generated: {generated}</div>
  {callout}
  {body}
</body>
</html>
""".format(
        title=escape(title_text),
        run_id=escape(run_id),
        generated=escape(generated_at),
        callout=callout_html,
        body=body_html,
    )


def render_treemap_html(run_id, treemap_items, topn, multi_run_note):
    selected = treemap_items[:topn]
    total = sum(item["bytes"] for item in selected)
    rows_html = []

    if total <= 0 or not selected:
        content = '<div class="panel"><div class="empty">No treemap-compatible byte items found in NDJSON.</div></div>'
    else:
        for item in selected:
            pct = (item["bytes"] * 100.0 / total) if total > 0 else 0.0
            flex_weight = max(1, int(round(pct * 100)))
            label = short_label(item["path"])
            tooltip = "{0} | {1} | {2:.2f}% of rendered total".format(
                item["path"], human_bytes(item["bytes"]), pct
            )
            row = (
                '<div class="tile" style="flex: {flex} 1 0%;" title="{tip}">'
                '<div class="tile-label">{label}</div>'
                '<div class="tile-meta">{size} ({pct:.2f}%)</div>'
                "</div>"
            ).format(
                flex=flex_weight,
                tip=escape(tooltip),
                label=escape(label),
                size=escape(human_bytes(item["bytes"])),
                pct=pct,
            )
            rows_html.append(row)

        content = (
            '<div class="note">Offender tiles are spotlights; totals not additive.</div>'
            '<div class="panel"><div class="treemap">{0}</div></div>'
        ).format("".join(rows_html))

    full = page_shell(
        title_text="Cleanup Audit Treemap Heatmap",
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        callout=multi_run_note,
        body_html=content,
    )
    return full


def render_timing_html(run_id, timing_items, topn, multi_run_note):
    selected = timing_items[:topn]
    total = sum(item["elapsed_ms"] for item in selected)
    rows_html = []

    if total <= 0 or not selected:
        content = '<div class="panel"><div class="empty">No timing events found in NDJSON.</div></div>'
    else:
        for item in selected:
            pct = (item["elapsed_ms"] * 100.0 / total) if total > 0 else 0.0
            width = max(2.0, pct)
            bar_text = "{0}: {1} ms ({2:.2f}%)".format(
                item["section"], item["elapsed_ms"], pct
            )
            row = (
                '<div class="bar-row">'
                '<div class="bar-fill" style="width:{w:.2f}%">{text}</div>'
                "</div>"
            ).format(w=width, text=escape(bar_text))
            rows_html.append(row)

        content = '<div class="panel"><div class="bars">{0}</div></div>'.format(
            "".join(rows_html)
        )

    full = page_shell(
        title_text="Cleanup Audit Timing Heatmap",
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        callout=multi_run_note,
        body_html=content,
    )
    return full


def ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        die("Failed to create output directory '{0}': {1}".format(path, exc))


def write_text(path, content):
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as exc:
        die("Failed writing file '{0}': {1}".format(path, exc))


def main():
    args = parse_args()
    if args.render_topn <= 0:
        die("--render-topn must be greater than 0")

    rows = read_ndjson(args.ndjson)
    run_id, selected_rows, multi_run_note = select_run(rows)
    treemap_items = collect_treemap_items(selected_rows)
    timing_items = collect_timing_items(selected_rows)

    ensure_dir(args.outdir)
    run_id_safe = safe_run_id(run_id)

    treemap_path = os.path.join(
        args.outdir, "heatmap-treemap-{0}.html".format(run_id_safe)
    )
    timing_path = os.path.join(
        args.outdir, "heatmap-timing-{0}.html".format(run_id_safe)
    )

    write_text(
        treemap_path,
        render_treemap_html(run_id=run_id, treemap_items=treemap_items, topn=args.render_topn, multi_run_note=multi_run_note),
    )
    write_text(
        timing_path,
        render_timing_html(run_id=run_id, timing_items=timing_items, topn=args.render_topn, multi_run_note=multi_run_note),
    )

    print("Wrote:")
    print(" - {0}".format(treemap_path))
    print(" - {0}".format(timing_path))


if __name__ == "__main__":
    main()
