#!/usr/bin/env bash
# =============================================================================
# Shared audit init module — defaults and common argument parsing
# Source this before lib/common.sh.
# =============================================================================

if [[ "${_AUDIT_INIT_SH_LOADED:-0}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi
_AUDIT_INIT_SH_LOADED=1

# Sets common audit defaults. Call before parse_args.
# Usage: audit_set_defaults_if_unset <module_name> <default_report_dir>
# Example: audit_set_defaults_if_unset "execution-audit" "execution-audit"
audit_set_defaults_if_unset() {
    local _default_report_dir="${2:-}"
    [[ -n "$_default_report_dir" ]] || _default_report_dir="audit"

    HOME_DIR="${HOME_DIR:-$HOME}"
    DEFAULT_REPORT_DIR="${DEFAULT_REPORT_DIR:-$(pwd)/output/$_default_report_dir}"
    REPORT_DIR="${REPORT_DIR:-$DEFAULT_REPORT_DIR}"
    NO_COLOR="${NO_COLOR:-false}"
    OUTPUT_FILE="${OUTPUT_FILE:-}"
    WRITE_NDJSON="${WRITE_NDJSON:-false}"
    REDACT_PATHS_MODE="${REDACT_PATHS_MODE:-auto}"
    REDACT_PATHS="${REDACT_PATHS:-false}"

    TIMESTAMP_FOR_FILENAME="${TIMESTAMP_FOR_FILENAME:-$(date +"%Y%m%d-%H%M%S")}"
    ISO_TIMESTAMP="${ISO_TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
    HOSTNAME_VAL="${HOSTNAME_VAL:-$(hostname 2>/dev/null || echo "unknown")}"
    CURRENT_USER="${CURRENT_USER:-$(id -un 2>/dev/null || echo "${USER:-unknown}")}"
    if [[ -z "${OS_VERSION:-}" ]]; then
        if command -v sw_vers >/dev/null 2>&1; then
            OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
        else
            OS_VERSION="unknown"
        fi
    fi
    KERNEL_INFO="${KERNEL_INFO:-$(uname -a 2>/dev/null || echo "unknown")}"
    if [[ -z "${RUN_ID:-}" ]] && command -v python3 >/dev/null 2>&1; then
        RUN_ID=$(python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || true)
    fi
    if [[ -z "${RUN_ID:-}" ]] && command -v uuidgen >/dev/null 2>&1; then
        RUN_ID=$(uuidgen 2>/dev/null || true)
    fi
    if [[ -z "${RUN_ID:-}" ]]; then
        RUN_ID="${TIMESTAMP_FOR_FILENAME}-$$"
    fi
}

# Parses common audit arguments. Usage function is called on --help or unknown arg.
# Usage: audit_parse_args <module_name> <usage_func> "$@"
# Example: audit_parse_args "execution" execution_usage "$@"
audit_parse_args() {
    local _usage_func="${2:-}"
    [[ -n "$_usage_func" ]] || _usage_func="usage"
    shift 2

    while (($# > 0)); do
        case "$1" in
            --report-dir)
                if (($# < 2)); then
                    echo "Error: --report-dir requires a path" >&2
                    "$_usage_func"
                    exit 1
                fi
                REPORT_DIR="$2"
                shift 2
                ;;
            --output)
                if (($# < 2)); then
                    echo "Error: --output requires a path" >&2
                    "$_usage_func"
                    exit 1
                fi
                OUTPUT_FILE="$2"
                shift 2
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
                "$_usage_func"
                exit 0
                ;;
            *)
                echo "Error: Unknown argument '$1'" >&2
                "$_usage_func"
                exit 1
                ;;
        esac
    done
}
