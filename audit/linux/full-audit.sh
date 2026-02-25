#!/usr/bin/env bash
# =============================================================================
# Linux Full System Audit
# Conservative mode — reports only, moves/deletes NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

# --- Defaults / Configuration ---
source "$(dirname "$0")/lib/init.sh"
audit_set_defaults_if_unset "full-audit"

LARGE_FILE_THRESHOLD_MB="${LARGE_FILE_THRESHOLD_MB:-100}"
OLD_FILE_DAYS="${OLD_FILE_DAYS:-180}"
DEEP_SCAN="${DEEP_SCAN:-false}"
ROOTS_OVERRIDE_RAW="${ROOTS_OVERRIDE_RAW:-}"
HEATMAP_EMIT_TOPN="${HEATMAP_EMIT_TOPN:-100}"
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

_ndjson_requested=$WRITE_NDJSON
audit_resolve_output_paths "full-audit"
# One shared probe-failure log across subshells (command substitutions)
export PROBE_FAILURES_FILE="$REPORT_DIR/.probe-failures-${RUN_ID}.tsv"
if $_ndjson_requested && ! $WRITE_NDJSON; then
    METADATA_NOTES+=("NDJSON disabled because python3 is unavailable")
fi

# --- Setup ---
mkdir -p "$REPORT_DIR"
SOFT_FAILURE_LOG="${SOFT_FAILURE_LOG:-$REPORT_DIR/.full-audit-soft-failures-$TIMESTAMP_FOR_FILENAME.log}"
: > "$SOFT_FAILURE_LOG"
TOP_NODE_MODULES_FILE="${TOP_NODE_MODULES_FILE:-$REPORT_DIR/.full-audit-top-node-modules-$TIMESTAMP_FOR_FILENAME.tsv}"
: > "$TOP_NODE_MODULES_FILE"
TOP_DOCUMENTS_FOLDERS_FILE="${TOP_DOCUMENTS_FOLDERS_FILE:-$REPORT_DIR/.full-audit-top-doc-folders-$TIMESTAMP_FOR_FILENAME.tsv}"
: > "$TOP_DOCUMENTS_FOLDERS_FILE"
TOP_PATHS_FILE="${TOP_PATHS_FILE:-$REPORT_DIR/.full-audit-top-paths-$TIMESTAMP_FOR_FILENAME.tsv}"
: > "$TOP_PATHS_FILE"
: > "$PROBE_FAILURES_FILE"

source "$(dirname "$0")/lib/common.sh"

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║              Linux Full System Audit             ║"
echo "║       Conservative Mode — Report Only            ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "Report will be saved to: ${GREEN}$REPORT_FILE${NC}"
echo ""

cat > "$REPORT_FILE" << EOF
# 🔍 Linux Full System Audit
**Generated:** $(date "+%B %d, %Y at %I:%M %p")
**Home Directory:** $HOME_DIR
**Mode:** Conservative (report only — nothing moved or deleted)

## Metadata
- **Timestamp (ISO-8601):** $ISO_TIMESTAMP
- **Run ID:** $RUN_ID
- **Hostname:** $HOSTNAME_VAL
- **Current user:** $CURRENT_USER
- **Distribution:** $OS_VERSION
- **Kernel:** \`$KERNEL_INFO\`
- **PATH:** \`$(get_audit_path_for_output)\`
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
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"full-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO"),\"path\":$(json_escape "$(get_audit_path_for_output)")}"
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
storage_prepare_files_and_common
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

emit_recommendations

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
emit_probe_failures_summary
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
xdg-open "$REPORT_FILE" 2>/dev/null || echo "Open: $REPORT_FILE"
echo ""
echo -e "${YELLOW}Remember: Nothing was moved or deleted. Review the report"
echo -e "and decide what actions to take.${NC}"
exit 0
