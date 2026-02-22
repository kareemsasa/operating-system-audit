#!/usr/bin/env bash
# =============================================================================
# Mac Full System Audit
# Conservative mode — reports only, moves/deletes NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

# --- Defaults / Configuration ---
HOME_DIR="$HOME"
DEFAULT_REPORT_DIR="$(pwd)/output/full-audit"
REPORT_DIR="${REPORT_DIR:-$DEFAULT_REPORT_DIR}"
LARGE_FILE_THRESHOLD_MB=100
OLD_FILE_DAYS=180
DEEP_SCAN=false
NO_COLOR=false
OUTPUT_FILE=""
WRITE_NDJSON=false
ROOTS_OVERRIDE_RAW=""
REDACT_PATHS_MODE="auto"
REDACT_PATHS=false
HEATMAP=false
HEATMAP_EMIT_TOPN=100
HEATMAP_RENDER_TOPN=50
declare -a METADATA_NOTES=()
declare -a NDJSON_PENDING_NOTES=()

usage() {
    cat << EOF
Usage: $(basename "$0") [options]

Options:
  --report-dir <path>    Output directory for Markdown report
  --output <path>        Exact Markdown output file path
  --roots <paths>        Comma-separated scan roots (overrides defaults/deep)
  --threshold-mb <int>   Large file threshold in MB (default: 100)
  --old-days <int>       Stale file threshold in days (default: 180)
  --deep                 Scan full home dir (pruned for Library/.Trash/.git/node_modules)
  --ndjson               Also write a compact NDJSON summary file
  --heatmap              Render HTML heatmaps (auto-enables NDJSON)
  --heatmap-emit-topn N  NDJSON top_paths/top_items emit count (default: 100)
  --heatmap-render-topn N Render count passed to HTML renderer (default: 50)
  --redact-paths         Redact NDJSON paths (default: on when --ndjson)
  --no-redact-paths      Disable NDJSON path redaction (default off otherwise)
  --no-color             Disable ANSI colors in terminal output
  -h, --help             Show this help and exit
EOF
}

while (($# > 0)); do
    case "$1" in
        --report-dir)
            if (($# < 2)); then
                echo "Error: --report-dir requires a path" >&2
                exit 1
            fi
            REPORT_DIR="$2"
            shift 2
            ;;
        --output)
            if (($# < 2)); then
                echo "Error: --output requires a path" >&2
                exit 1
            fi
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --roots)
            if (($# < 2)); then
                echo "Error: --roots requires a comma-separated path list" >&2
                exit 1
            fi
            ROOTS_OVERRIDE_RAW="$2"
            shift 2
            ;;
        --threshold-mb)
            if (($# < 2)); then
                echo "Error: --threshold-mb requires an integer" >&2
                exit 1
            fi
            LARGE_FILE_THRESHOLD_MB="$2"
            shift 2
            ;;
        --old-days)
            if (($# < 2)); then
                echo "Error: --old-days requires an integer" >&2
                exit 1
            fi
            OLD_FILE_DAYS="$2"
            shift 2
            ;;
        --deep)
            DEEP_SCAN=true
            shift
            ;;
        --ndjson)
            WRITE_NDJSON=true
            shift
            ;;
        --heatmap)
            HEATMAP=true
            shift
            ;;
        --heatmap-emit-topn)
            if (($# < 2)); then
                echo "Error: --heatmap-emit-topn requires an integer" >&2
                exit 1
            fi
            HEATMAP_EMIT_TOPN="$2"
            shift 2
            ;;
        --heatmap-render-topn)
            if (($# < 2)); then
                echo "Error: --heatmap-render-topn requires an integer" >&2
                exit 1
            fi
            HEATMAP_RENDER_TOPN="$2"
            shift 2
            ;;
        --redact-paths)
            REDACT_PATHS_MODE="on"
            shift
            ;;
        --no-redact-paths)
            REDACT_PATHS_MODE="off"
            shift
            ;;
        --no-color)
            NO_COLOR=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$1'" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ ! "$LARGE_FILE_THRESHOLD_MB" =~ ^[0-9]+$ ]]; then
    echo "Error: --threshold-mb must be a non-negative integer" >&2
    exit 1
fi

if [[ ! "$OLD_FILE_DAYS" =~ ^[0-9]+$ ]]; then
    echo "Error: --old-days must be a non-negative integer" >&2
    exit 1
fi

if [[ ! "$HEATMAP_EMIT_TOPN" =~ ^[0-9]+$ ]] || (( HEATMAP_EMIT_TOPN <= 0 )); then
    echo "Error: --heatmap-emit-topn must be a positive integer" >&2
    exit 1
fi

if [[ ! "$HEATMAP_RENDER_TOPN" =~ ^[0-9]+$ ]] || (( HEATMAP_RENDER_TOPN <= 0 )); then
    echo "Error: --heatmap-render-topn must be a positive integer" >&2
    exit 1
fi

TIMESTAMP_FOR_FILENAME=$(date +"%Y%m%d-%H%M%S")
ISO_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
CURRENT_USER=$(id -un 2>/dev/null || echo "${USER:-unknown}")
if command -v sw_vers >/dev/null 2>&1; then
    OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
else
    OS_VERSION="unknown"
fi
KERNEL_INFO=$(uname -a 2>/dev/null || echo "unknown")
if command -v python3 >/dev/null 2>&1; then
    RUN_ID=$(python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || true)
else
    RUN_ID=""
fi
if [ -z "${RUN_ID:-}" ] && command -v uuidgen >/dev/null 2>&1; then
    RUN_ID=$(uuidgen 2>/dev/null || true)
fi
if [ -z "${RUN_ID:-}" ]; then
    RUN_ID="${TIMESTAMP_FOR_FILENAME}-$$"
fi

if $HEATMAP && ! $WRITE_NDJSON; then
    WRITE_NDJSON=true
fi

if $WRITE_NDJSON; then
    case "$REDACT_PATHS_MODE" in
        on) REDACT_PATHS=true ;;
        off) REDACT_PATHS=false ;;
        auto) REDACT_PATHS=true ;;
    esac
fi

if [ -n "$OUTPUT_FILE" ]; then
    REPORT_FILE="$OUTPUT_FILE"
    REPORT_DIR=$(dirname "$REPORT_FILE")
else
    REPORT_FILE="$REPORT_DIR/full-audit-$TIMESTAMP_FOR_FILENAME.md"
fi

# --- Setup ---
mkdir -p "$REPORT_DIR"
SOFT_FAILURE_LOG="$REPORT_DIR/.full-audit-soft-failures-$TIMESTAMP_FOR_FILENAME.log"
: > "$SOFT_FAILURE_LOG"
TOP_NODE_MODULES_FILE="$REPORT_DIR/.full-audit-top-node-modules-$TIMESTAMP_FOR_FILENAME.tsv"
: > "$TOP_NODE_MODULES_FILE"
TOP_DOCUMENTS_FOLDERS_FILE="$REPORT_DIR/.full-audit-top-doc-folders-$TIMESTAMP_FOR_FILENAME.tsv"
: > "$TOP_DOCUMENTS_FOLDERS_FILE"
TOP_PATHS_FILE="$REPORT_DIR/.full-audit-top-paths-$TIMESTAMP_FOR_FILENAME.tsv"
: > "$TOP_PATHS_FILE"

NDJSON_FILE=""
if $WRITE_NDJSON; then
    report_base="${REPORT_FILE%.*}"
    if [ "$report_base" = "$REPORT_FILE" ]; then
        NDJSON_FILE="${REPORT_FILE}.ndjson"
    else
        NDJSON_FILE="${report_base}.ndjson"
    fi
fi

if $WRITE_NDJSON && ! command -v python3 >/dev/null 2>&1; then
    echo "Warning: --ndjson requested but python3 is unavailable; disabling NDJSON output." >&2
    METADATA_NOTES+=("NDJSON disabled because python3 is unavailable")
    WRITE_NDJSON=false
    REDACT_PATHS=false
    NDJSON_FILE=""
fi

source "$(dirname "$0")/lib/common.sh"

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║              Mac Full System Audit               ║"
echo "║       Conservative Mode — Report Only            ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "Report will be saved to: ${GREEN}$REPORT_FILE${NC}"
echo ""

cat > "$REPORT_FILE" << EOF
# 🔍 Mac Full System Audit
**Generated:** $(date "+%B %d, %Y at %I:%M %p")
**Home Directory:** $HOME_DIR
**Mode:** Conservative (report only — nothing moved or deleted)

## Metadata
- **Timestamp (ISO-8601):** $ISO_TIMESTAMP
- **Run ID:** $RUN_ID
- **Hostname:** $HOSTNAME_VAL
- **Current user:** $CURRENT_USER
- **macOS product version:** $OS_VERSION
- **Kernel:** \`$KERNEL_INFO\`
EOF
for note in "${METADATA_NOTES[@]+"${METADATA_NOTES[@]}"}"; do
    echo "- **Note:** $note" >> "$REPORT_FILE"
done
echo "" >> "$REPORT_FILE"
echo "---" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
STORAGE_HEADER_READY=true

if [ -n "$NDJSON_FILE" ]; then
    : > "$NDJSON_FILE"
    scan_mode="scoped"
    if $DEEP_SCAN && [ -z "$ROOTS_OVERRIDE_RAW" ]; then
        scan_mode="deep"
    fi
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"full-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO")}"
    append_ndjson_line "{\"type\":\"scan\",\"run_id\":$(json_escape "$RUN_ID"),\"mode\":$(json_escape "$scan_mode"),\"threshold_mb\":$LARGE_FILE_THRESHOLD_MB,\"old_days\":$OLD_FILE_DAYS,\"redact_paths\":$([ "$REDACT_PATHS" = true ] && echo true || echo false)}"
    STORAGE_NDJSON_INITIALIZED=true
fi

source "$(dirname "$0")/storage.sh"
source "$(dirname "$0")/network.sh"
source "$(dirname "$0")/identity.sh"
source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/execution.sh"
source "$(dirname "$0")/persistence.sh"
storage_build_scan_roots
for note in "${NDJSON_PENDING_NOTES[@]+"${NDJSON_PENDING_NOTES[@]}"}"; do
    if [ -n "$NDJSON_FILE" ]; then
        append_ndjson_line "{\"type\":\"note\",\"run_id\":$(json_escape "$RUN_ID"),\"message\":$(json_escape "$note")}"
    fi
done
run_storage_audit
if ! run_network_audit; then
    append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"network_audit_failed\"}"
fi
if ! run_identity_audit; then
    append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"identity_audit_failed\"}"
fi
if ! run_config_audit; then
    append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"config_audit_failed\"}"
fi
if ! run_execution_audit; then
    append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"execution_audit_failed\"}"
fi
if ! run_persistence_audit; then
    append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"persistence_audit_failed\"}"
fi

HEATMAP_TREEMAP_FILE=""
HEATMAP_TIMING_FILE=""
if $HEATMAP && [ -n "$NDJSON_FILE" ]; then
    if ! command -v python3 >/dev/null 2>&1; then
        append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"python3_missing_heatmaps_skipped\"}"
    else
        if [ -n "${OSAUDIT_ROOT:-}" ]; then
            REPO_ROOT="$OSAUDIT_ROOT"
        else
            REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
        fi
        if python3 "$REPO_ROOT/core/render_heatmaps.py" --ndjson "$NDJSON_FILE" --outdir "$REPORT_DIR" --render-topn "$HEATMAP_RENDER_TOPN"; then
            run_id_safe=$(sanitize_run_id_for_filename "$RUN_ID")
            candidate_treemap="$REPORT_DIR/heatmap-treemap-${run_id_safe}.html"
            candidate_timing="$REPORT_DIR/heatmap-timing-${run_id_safe}.html"
            if [ -f "$candidate_treemap" ] && [ -f "$candidate_timing" ]; then
                HEATMAP_TREEMAP_FILE="$candidate_treemap"
                HEATMAP_TIMING_FILE="$candidate_timing"
            fi
        else
            append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"heatmap_render_failed\"}"
        fi
    fi
fi

section_header "📋 Suggested Organization Plan"

cat >> "$REPORT_FILE" << 'EOF'
Based on the audit above, here's a recommended folder structure for your home directory:

```
~/Documents/
├── Work/
│   ├── RCG/
│   │   ├── PowerHub/
│   │   ├── Navitas/
│   │   ├── Milford-Mining/
│   │   └── USMED-Equip/
│   └── Contracts-Invoices/
├── Projects/
│   ├── Arachne/
│   └── Personal-Dev/
├── Finance/
│   ├── Taxes/
│   └── Receipts/
├── Education/
│   └── Certifications/
└── Archive/
    └── (older files, organized by year)

~/Downloads/
├── (keep clean — process files then move or delete)

~/Desktop/
├── (keep minimal — temporary workspace only)
```

### Recommended Next Steps

1. **Quick wins:** Empty Trash, delete .dmg/.pkg installers you no longer need
2. **Downloads purge:** Sort through old downloads — delete or file away
3. **Desktop triage:** Move Desktop items into proper Documents subfolders
4. **Dev cleanup:** Remove unused `node_modules` with `npx npkill`
5. **Duplicate cleanup:** Review flagged copies and remove extras
6. **Ongoing habit:** Process Downloads weekly, keep Desktop under 10 items
EOF

if [ -n "$HEATMAP_TREEMAP_FILE" ] && [ -n "$HEATMAP_TIMING_FILE" ]; then
    cat >> "$REPORT_FILE" << EOF

## 🗺️ Visualizations
- Heatmaps are best-effort artifacts and may be skipped if rendering prerequisites fail.
- Treemap heatmap: \`$HEATMAP_TREEMAP_FILE\`
- Timing heatmap: \`$HEATMAP_TIMING_FILE\`
EOF
fi

echo -e "\n${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║              Audit Complete! ✅                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "Full report saved to:"
echo -e "  ${CYAN}$REPORT_FILE${NC}"
if [ -n "$NDJSON_FILE" ]; then
    echo -e "NDJSON summary saved to:"
    echo -e "  ${CYAN}$NDJSON_FILE${NC}"
fi
soft_failures=0
if [ -f "$SOFT_FAILURE_LOG" ]; then
    soft_failures=$(wc -l < "$SOFT_FAILURE_LOG" | tr -d ' ' || true)
    soft_failures=${soft_failures:-0}
fi
rm -f "$SOFT_FAILURE_LOG" "$TOP_NODE_MODULES_FILE" "$TOP_DOCUMENTS_FOLDERS_FILE" "$TOP_PATHS_FILE" || true
if (( soft_failures > 0 )); then
    echo -e "Soft probe warnings encountered: ${YELLOW}$soft_failures${NC}"
    echo "- **Soft probe warnings:** $soft_failures" >> "$REPORT_FILE"
    if [ -n "$NDJSON_FILE" ]; then
        append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"soft_failures\":${soft_failures:-0}}"
    fi
fi
echo ""
echo -e "Open it with:  ${BOLD}open \"$REPORT_FILE\"${NC}"
echo ""
echo -e "${YELLOW}Remember: Nothing was moved or deleted. Review the report"
echo -e "and decide what actions to take.${NC}"
exit 0
