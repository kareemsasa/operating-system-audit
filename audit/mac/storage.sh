#!/usr/bin/env bash
# =============================================================================
# Mac Storage Audit (sections 1-9 from cleanup audit)
# Conservative mode — reports only, moves/deletes NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

storage_usage() {
    cat << EOF
Usage: $(basename "${BASH_SOURCE[0]}") [options]

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

storage_set_defaults_if_unset() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_defaults_if_unset "cleanup-audit"

    LARGE_FILE_THRESHOLD_MB="${LARGE_FILE_THRESHOLD_MB:-100}"
    OLD_FILE_DAYS="${OLD_FILE_DAYS:-180}"
    DEEP_SCAN="${DEEP_SCAN:-false}"
    ROOTS_OVERRIDE_RAW="${ROOTS_OVERRIDE_RAW:-}"
    HEATMAP="${HEATMAP:-false}"
    HEATMAP_EMIT_TOPN="${HEATMAP_EMIT_TOPN:-100}"
    HEATMAP_RENDER_TOPN="${HEATMAP_RENDER_TOPN:-50}"

    if [[ -z "${METADATA_NOTES+x}" ]]; then
        METADATA_NOTES=()
    fi
    if [[ -z "${NDJSON_PENDING_NOTES+x}" ]]; then
        NDJSON_PENDING_NOTES=()
    fi
}

storage_parse_args() {
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
                storage_usage
                exit 0
                ;;
            *)
                echo "Error: Unknown argument '$1'" >&2
                storage_usage
                exit 1
                ;;
        esac
    done
}

storage_validate_and_resolve_paths() {
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

    if $HEATMAP && ! $WRITE_NDJSON; then
        WRITE_NDJSON=true
    fi

    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_resolve_output_paths "cleanup-audit"
    if ! command -v python3 >/dev/null 2>&1 && $HEATMAP; then
        METADATA_NOTES+=("NDJSON disabled because python3 is unavailable")
    fi
}

storage_build_scan_roots() {
    SCAN_ROOTS=()
    if $DEEP_SCAN; then
        SCAN_ROOTS=("$HOME_DIR")
    else
        SCAN_ROOTS=("$HOME_DIR/Downloads" "$HOME_DIR/Desktop" "$HOME_DIR/Documents")
    fi

    if [ -n "$ROOTS_OVERRIDE_RAW" ]; then
        SCAN_ROOTS=()
        declare -a requested_roots=()
        IFS=',' read -r -a requested_roots <<< "$ROOTS_OVERRIDE_RAW"
        for root in "${requested_roots[@]+"${requested_roots[@]}"}"; do
            trimmed_root=$(echo "$root" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
            [ -n "$trimmed_root" ] || continue
            if [ -e "$trimmed_root" ]; then
                SCAN_ROOTS+=("$trimmed_root")
            else
                note_msg="Skipping missing root: $trimmed_root"
                METADATA_NOTES+=("$note_msg")
                NDJSON_PENDING_NOTES+=("$note_msg")
            fi
        done
        if ((${#SCAN_ROOTS[@]} == 0)); then
            note_msg="No valid scan roots from --roots; scoped scans will return no matches"
            METADATA_NOTES+=("$note_msg")
            NDJSON_PENDING_NOTES+=("$note_msg")
        fi
    fi
}

storage_prepare_files_and_common() {
    mkdir -p "$REPORT_DIR"
    SOFT_FAILURE_LOG="${SOFT_FAILURE_LOG:-$REPORT_DIR/.cleanup-audit-soft-failures-$TIMESTAMP_FOR_FILENAME.log}"
    : > "$SOFT_FAILURE_LOG"
    TOP_NODE_MODULES_FILE="${TOP_NODE_MODULES_FILE:-$REPORT_DIR/.cleanup-audit-top-node-modules-$TIMESTAMP_FOR_FILENAME.tsv}"
    : > "$TOP_NODE_MODULES_FILE"
    TOP_DOCUMENTS_FOLDERS_FILE="${TOP_DOCUMENTS_FOLDERS_FILE:-$REPORT_DIR/.cleanup-audit-top-doc-folders-$TIMESTAMP_FOR_FILENAME.tsv}"
    : > "$TOP_DOCUMENTS_FOLDERS_FILE"
    TOP_PATHS_FILE="${TOP_PATHS_FILE:-$REPORT_DIR/.cleanup-audit-top-paths-$TIMESTAMP_FOR_FILENAME.tsv}"
    : > "$TOP_PATHS_FILE"

    # Set shared variables before sourcing common library.
    source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
    source "$(dirname "${BASH_SOURCE[0]}")/lib/scan.sh"
}

storage_write_report_header_if_needed() {
    if [[ "${STORAGE_HEADER_READY:-false}" == "true" ]]; then
        return 0
    fi
    cat > "$REPORT_FILE" << EOF
# 🧹 Mac Home Directory Cleanup Audit
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
}

storage_init_ndjson_if_needed() {
    if [ -z "$NDJSON_FILE" ]; then
        return 0
    fi
    if [[ "${STORAGE_NDJSON_INITIALIZED:-false}" == "true" ]]; then
        return 0
    fi
    : > "$NDJSON_FILE"
    scan_mode="scoped"
    if $DEEP_SCAN && [ -z "$ROOTS_OVERRIDE_RAW" ]; then
        scan_mode="deep"
    fi
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"home-cleanup-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO")}"
    append_ndjson_line "{\"type\":\"scan\",\"run_id\":$(json_escape "$RUN_ID"),\"mode\":$(json_escape "$scan_mode"),\"threshold_mb\":$LARGE_FILE_THRESHOLD_MB,\"old_days\":$OLD_FILE_DAYS,\"redact_paths\":$([ "$REDACT_PATHS" = true ] && echo true || echo false)}"
    for note in "${NDJSON_PENDING_NOTES[@]+"${NDJSON_PENDING_NOTES[@]}"}"; do
        append_ndjson_line "{\"type\":\"note\",\"run_id\":$(json_escape "$RUN_ID"),\"message\":$(json_escape "$note")}"
    done
    STORAGE_NDJSON_INITIALIZED=true
}

storage_render_heatmaps_if_requested() {
    if ! $HEATMAP || [ -z "$NDJSON_FILE" ]; then
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Warning: --heatmap requested but python3 is unavailable; skipping heatmaps." >&2
        append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"python3_missing_heatmaps_skipped\"}"
        return 0
    fi
    if [ -n "${OSAUDIT_ROOT:-}" ]; then
        REPO_ROOT="$OSAUDIT_ROOT"
    else
        REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    fi
    if python3 "$REPO_ROOT/core/render_heatmaps.py" --ndjson "$NDJSON_FILE" --outdir "$REPORT_DIR" --render-topn "$HEATMAP_RENDER_TOPN"; then
        run_id_safe=$(sanitize_run_id_for_filename "$RUN_ID")
        candidate_treemap="$REPORT_DIR/heatmap-treemap-${run_id_safe}.html"
        candidate_timing="$REPORT_DIR/heatmap-timing-${run_id_safe}.html"
        if [ -f "$candidate_treemap" ] && [ -f "$candidate_timing" ]; then
            echo "" >> "$REPORT_FILE"
            echo "---" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
            echo "## 🗺️ Visualizations" >> "$REPORT_FILE"
            echo "- Treemap heatmap: \`$candidate_treemap\`" >> "$REPORT_FILE"
            echo "- Timing heatmap: \`$candidate_timing\`" >> "$REPORT_FILE"
        fi
    else
        append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"code\":\"heatmap_render_failed\"}"
    fi
}

storage_main() {
    storage_set_defaults_if_unset
    storage_parse_args "$@"
    storage_validate_and_resolve_paths
    storage_build_scan_roots
    storage_prepare_files_and_common
    storage_write_report_header_if_needed
    storage_init_ndjson_if_needed
    run_storage_audit
    emit_recommendations
    storage_render_heatmaps_if_requested
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    storage_main "$@"
fi
