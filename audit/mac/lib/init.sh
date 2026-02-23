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
# Usage: audit_set_defaults_if_unset <default_report_dir>
# Example: audit_set_defaults_if_unset "execution-audit"
audit_set_defaults_if_unset() {
    local _default_report_dir="${1:-}"
    [[ -n "$_default_report_dir" ]] || _default_report_dir="audit"

    HOME_DIR="${HOME_DIR:-$HOME}"
    # Ensure core macOS admin binaries exist even in non-login / GUI contexts
    export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:${PATH:-}"
    AUDIT_PATH="${AUDIT_PATH:-$PATH}"
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
    local _module="${1:-}"
    local _usage_func="${2:-}"
    [[ -n "$_usage_func" ]] || _usage_func="usage"
    shift 2

    _err() {
        if [[ -n "$_module" ]]; then
            echo "Error [$_module]: $*" >&2
        else
            echo "Error: $*" >&2
        fi
    }

    while (($# > 0)); do
        case "$1" in
            --report-dir)
                if (($# < 2)); then
                    _err "--report-dir requires a path"
                    "$_usage_func"
                    exit 1
                fi
                REPORT_DIR="$2"
                shift 2
                ;;
            --output)
                if (($# < 2)); then
                    _err "--output requires a path"
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
                _err "Unknown argument '$1'"
                "$_usage_func"
                exit 1
                ;;
        esac
    done
}

# Resolves REPORT_FILE, REPORT_DIR, NDJSON_FILE, REDACT_PATHS. Call after parse_args.
# Handles NDJSON/redact-paths logic and python3 availability check.
# Usage: audit_resolve_output_paths <report_suffix>
# Example: audit_resolve_output_paths "config-audit"
audit_resolve_output_paths() {
    local report_suffix="${1:-audit}"

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
        REPORT_FILE="${REPORT_FILE:-$REPORT_DIR/${report_suffix}-$TIMESTAMP_FOR_FILENAME.md}"
    fi

    NDJSON_FILE="${NDJSON_FILE:-}"
    if $WRITE_NDJSON && [ -z "$NDJSON_FILE" ]; then
        report_base="${REPORT_FILE%.*}"
        if [ "$report_base" = "$REPORT_FILE" ]; then
            NDJSON_FILE="${REPORT_FILE}.ndjson"
        else
            NDJSON_FILE="${report_base}.ndjson"
        fi
    fi

    if $WRITE_NDJSON && ! command -v python3 >/dev/null 2>&1; then
        echo "Warning: --ndjson requested but python3 is unavailable; disabling NDJSON output." >&2
        WRITE_NDJSON=false
        REDACT_PATHS=false
        NDJSON_FILE=""
    fi
}

export AUDIT_INIT_LOADED=1
