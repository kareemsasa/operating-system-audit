#!/usr/bin/env bash

if [[ "${_COMMON_SH_LOADED:-0}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi
_COMMON_SH_LOADED=1

# Initialize before any trap/cleanup; avoids unbound variable with set -u when trap runs
declare -a _COMMON_TMPFILES=()

_common_require_var_set() {
    local name="$1"
    if [[ -z "${!name+x}" ]]; then
        echo "Error: common.sh requires '$name' to be set before sourcing." >&2
        return 1
    fi
}

_common_require_var_nonempty() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        echo "Error: common.sh requires non-empty '$name' before sourcing." >&2
        return 1
    fi
}

_common_validate_required_context() {
    [ "${AUDIT_INIT_LOADED:-}" = "1" ] || { echo "Error: common.sh requires init.sh to be sourced first" >&2; return 1; }
    _common_require_var_set "NO_COLOR" || return 1
    _common_require_var_set "NDJSON_FILE" || return 1
    _common_require_var_set "RUN_ID" || return 1
    _common_require_var_set "REPORT_FILE" || return 1
    _common_require_var_set "SOFT_FAILURE_LOG" || return 1
    _common_require_var_set "REDACT_PATHS" || return 1
    _common_require_var_set "HOME_DIR" || return 1
    _common_require_var_set "CURRENT_USER" || return 1

    _common_require_var_nonempty "RUN_ID" || return 1
    _common_require_var_nonempty "REPORT_FILE" || return 1
    _common_require_var_nonempty "SOFT_FAILURE_LOG" || return 1
    _common_require_var_nonempty "HOME_DIR" || return 1
    _common_require_var_nonempty "CURRENT_USER" || return 1
}

_common_validate_required_context || {
    return 1 2>/dev/null || exit 1
}

# Temp file cleanup - run on EXIT/INT/TERM
_common_register_tmp() {
    local f="$1"
    [[ -n "$f" ]] && _COMMON_TMPFILES+=("$f")
}

_common_cleanup_tmps() {
    local f
    for f in "${_COMMON_TMPFILES[@]+"${_COMMON_TMPFILES[@]}"}"; do
        [[ -n "$f" ]] && rm -f "$f" 2>/dev/null || true
    done
    _COMMON_TMPFILES=()
}

if [[ "${_COMMON_CLEANUP_TRAP_SET:-0}" != "1" ]]; then
    trap _common_cleanup_tmps EXIT INT TERM
    _COMMON_CLEANUP_TRAP_SET=1
fi

_common_is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

# Colors
if _common_is_true "$NO_COLOR"; then
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    BOLD=''
    NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${1-}"
}

stat_bytes() {
    local path="$1"
    stat -f%z "$path" 2>/dev/null || stat -c%s "$path" 2>/dev/null || echo 0
}

dir_bytes() {
    local path="$1"
    local kib=0
    if [ ! -d "$path" ]; then
        echo 0
        return 0
    fi
    kib=$(du -sk "$path" 2>/dev/null | awk '{print $1}' || true)
    kib=${kib:-0}
    echo $((kib * 1024))
}

append_ndjson_line() {
    [ -n "$NDJSON_FILE" ] || return 0
    echo "$1" >> "$NDJSON_FILE"
}

# Returns AUDIT_PATH for output; redacted when REDACT_PATHS. Use for report/NDJSON only.
get_audit_path_for_output() {
    local p="${AUDIT_PATH:-}"
    if _common_is_true "$REDACT_PATHS"; then
        p="$(echo "$p" | sed "s#$HOME_DIR#~#g; s#/${CURRENT_USER}/#/<user>/#g")"
    fi
    echo "$p"
}

redact_path_for_ndjson() {
    local input_path="$1"
    if ! _common_is_true "$REDACT_PATHS"; then
        echo "$input_path"
        return
    fi

    case "$input_path" in
        "$HOME_DIR")
            echo "~"
            ;;
        "$HOME_DIR"/*)
            echo "~/${input_path#$HOME_DIR/}"
            ;;
        *)
            if [ -n "$CURRENT_USER" ]; then
                echo "$input_path" | sed "s#/${CURRENT_USER}/#/<user>/#g; s#/${CURRENT_USER}\$#/<user>#"
            else
                echo "$input_path"
            fi
            ;;
    esac
}

now_ms() {
    if command -v perl >/dev/null 2>&1; then
        perl -MTime::HiRes=time -e 'printf("%.0f\n", time()*1000)'
    else
        echo $(( $(date +%s) * 1000 ))
    fi
}

emit_timing() {
    [ -n "$NDJSON_FILE" ] || return 0
    local section="$1"
    local start_ms="$2"
    local end_ms="$3"
    local elapsed_ms=$((end_ms - start_ms))
    append_ndjson_line "{\"type\":\"timing\",\"run_id\":$(json_escape "$RUN_ID"),\"section\":$(json_escape "$section"),\"elapsed_ms\":$elapsed_ms}"
}

section_header() {
    echo -e "\n${BOLD}${YELLOW}━━━ $1 ━━━${NC}"
    echo -e "\n## $1\n" >> "$REPORT_FILE"
}

count_lines() {
    local n
    n=$(wc -l | tr -d ' ' || true)
    echo "${n:-0}"
}

record_soft_failure() {
    [ -n "${SOFT_FAILURE_LOG:-}" ] || return 0
    echo "${1:-probe_failed}" >> "$SOFT_FAILURE_LOG"
}

# count_key: optional 4th arg; used for probe_failures_summary grouping. When omitted, uses probe.
# message: optional 5th arg; first line of stderr (when AUDIT_CAPTURE_STDERR). Truncated to 200 chars.
# For soft/soft_out pass argv0 (basename) to avoid cardinality explosion from variable args.
emit_probe_failed() {
    [ -n "$NDJSON_FILE" ] || return 0
    local probe="$1"
    local code="${2:-1}"
    # Never record success as failure; exit 0 means probe succeeded.
    [ "$code" -ne 0 ] 2>/dev/null || return 0
    local argv0="${3:-}"
    local count_key="${4:-$probe}"
    local message="${5:-}"
    local pf_file="${PROBE_FAILURES_FILE:-}"
    [ -n "$pf_file" ] || pf_file="$(dirname "$REPORT_FILE")/.probe-failures-$$.tmp"
    PROBE_FAILURES_FILE="$pf_file"
    local ts
    ts=$(now_ms)
    if ! printf '%s\t%s\t%s\n' "$count_key" "$ts" "${code:-1}" >> "$pf_file" 2>/dev/null; then
        record_soft_failure "probe_failures_file_write_failed:$pf_file"
    fi
    local msg_json=""
    [ -n "$message" ] && msg_json=",\"message\":$(json_escape "$message")"
    append_ndjson_line "{\"type\":\"probe_failed\",\"run_id\":$(json_escape "$RUN_ID"),\"probe\":$(json_escape "$probe"),\"argv0\":$(json_escape "$argv0"),\"exit_code\":${code:-1},\"ts_ms\":${ts}${msg_json}}"
}

emit_probe_failures_summary() {
    [ -n "$NDJSON_FILE" ] || return 0
    local pf_file="${PROBE_FAILURES_FILE:-$(dirname "$REPORT_FILE")/.probe-failures-$$.tmp}"
    [ -f "$pf_file" ] || return 0
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
    local summary_json
    summary_json=$(RUN_ID="${RUN_ID:-}" python3 "$repo_root/core/probe_failures_summary.py" "$pf_file" 2>/dev/null)
    rm -f "$pf_file" 2>/dev/null || true
    [ -n "$summary_json" ] || return 0
    append_ndjson_line "$summary_json"
}

# Redaction order: HOME_DIR first, then CURRENT_USER, then generic /Users/username/ (network home dirs, etc).
# Only run /Users/.../ replacement if string still contains /Users/ (avoid double-sanitizing /<user>/).
# Strips ANSI: SGR (\x1b\[...m), CSI (\x1b\[...[a-zA-Z]), OSC (\x1b\]...\x07 or \x1b\]...\x1b\\).
_soft_capture_stderr_msg() {
    local f="$1"
    [ -f "$f" ] || return
    local msg
    msg=$(head -1 "$f" 2>/dev/null | cut -c1-200)
    msg=$(echo "$msg" | sed -e "s#${HOME_DIR}#~#g" -e "s#/${CURRENT_USER}/#/<user>/#g")
    [[ "$msg" == *"/Users/"* ]] && msg=$(echo "$msg" | sed "s#/Users/[^/]*/#/<user>/#g")
    echo "$msg" | sed \
        -e 's/\x1b\[[0-9;]*m//g' \
        -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
        -e $'s/\x1b\\][^\x07]*\x07//g' \
        -e $'s/\x1b\\][^\x1b]*\x1b\\\\//g'
}

# INTERNAL/LEGACY: Prefer soft_probe() with explicit probe names. Do not add new callers.
soft() {
    if _common_is_true "${AUDIT_CAPTURE_STDERR:-false}"; then
        local stderr_tmp
        stderr_tmp=$(mktemp -t audit_stderr.XXXXXX 2>/dev/null)
        _common_register_tmp "$stderr_tmp"
        if "$@" 2>"${stderr_tmp:-/dev/null}"; then
            rm -f "$stderr_tmp" 2>/dev/null
            return 0
        fi
        local code=$?
        local msg
        msg=$(_soft_capture_stderr_msg "$stderr_tmp")
        record_soft_failure "soft:$*"
        emit_probe_failed "$*" "$code" "${1:-}" "$(basename "${1:-}" 2>/dev/null || echo "${1:-}")" "$msg"
        rm -f "$stderr_tmp" 2>/dev/null
        return 0
    fi
    "$@" 2>/dev/null || {
        local code=$?
        record_soft_failure "soft:$*"
        emit_probe_failed "$*" "$code" "${1:-}" "$(basename "${1:-}" 2>/dev/null || echo "${1:-}")"
        return 0
    }
}

# INTERNAL/LEGACY: Prefer soft_out_probe() with explicit probe names. Do not add new callers.
soft_out() {
    if _common_is_true "${AUDIT_CAPTURE_STDERR:-false}"; then
        local stderr_tmp
        stderr_tmp=$(mktemp -t audit_stderr.XXXXXX 2>/dev/null)
        _common_register_tmp "$stderr_tmp"
        local out
        out=$("$@" 2>"${stderr_tmp:-/dev/null}")
        local code=$?
        if [ $code -eq 0 ]; then
            rm -f "$stderr_tmp" 2>/dev/null
            echo "$out"
            return 0
        fi
        local msg
        msg=$(_soft_capture_stderr_msg "$stderr_tmp")
        record_soft_failure "soft_out:$*"
        emit_probe_failed "$*" "$code" "${1:-}" "$(basename "${1:-}" 2>/dev/null || echo "${1:-}")" "$msg"
        rm -f "$stderr_tmp" 2>/dev/null
        return 0
    fi
    "$@" 2>/dev/null || {
        local code=$?
        record_soft_failure "soft_out:$*"
        emit_probe_failed "$*" "$code" "${1:-}" "$(basename "${1:-}" 2>/dev/null || echo "${1:-}")"
        return 0
    }
}

soft_probe() {
    local probe="$1"; shift
    if _common_is_true "${AUDIT_CAPTURE_STDERR:-false}"; then
        local stderr_tmp
        stderr_tmp=$(mktemp -t audit_stderr.XXXXXX 2>/dev/null)
        _common_register_tmp "$stderr_tmp"
        if "$@" 2>"${stderr_tmp:-/dev/null}"; then
            rm -f "$stderr_tmp" 2>/dev/null
            return 0
        fi
        local code=$?
        local msg
        msg=$(_soft_capture_stderr_msg "$stderr_tmp")
        record_soft_failure "soft_probe:${probe}:$*"
        emit_probe_failed "$probe" "$code" "${1:-}" "" "$msg"
        rm -f "$stderr_tmp" 2>/dev/null
        return 0
    fi
    "$@" 2>/dev/null || {
        local code=$?
        record_soft_failure "soft_probe:${probe}:$*"
        emit_probe_failed "$probe" "$code" "${1:-}"
        return 0
    }
}

soft_out_probe() {
    local probe="$1"; shift
    if _common_is_true "${AUDIT_CAPTURE_STDERR:-false}"; then
        local stderr_tmp
        stderr_tmp=$(mktemp -t audit_stderr.XXXXXX 2>/dev/null)
        _common_register_tmp "$stderr_tmp"
        local out
        out=$("$@" 2>"${stderr_tmp:-/dev/null}")
        local code=$?
        if [ $code -eq 0 ]; then
            rm -f "$stderr_tmp" 2>/dev/null
            echo "$out"
            return 0
        fi
        local msg
        msg=$(_soft_capture_stderr_msg "$stderr_tmp")
        record_soft_failure "soft_out_probe:${probe}:$*"
        emit_probe_failed "$probe" "$code" "${1:-}" "" "$msg"
        rm -f "$stderr_tmp" 2>/dev/null
        return 0
    fi
    "$@" 2>/dev/null || {
        local code=$?
        record_soft_failure "soft_out_probe:${probe}:$*"
        emit_probe_failed "$probe" "$code" "${1:-}"
        return 0
    }
}

# Like soft_probe but returns the actual exit code (doesn't swallow on failure).
# Use for probes where the caller needs the real exit code (e.g. admin check).
soft_probe_check() {
    local probe="$1"; shift
    if _common_is_true "${AUDIT_CAPTURE_STDERR:-false}"; then
        local stderr_tmp
        stderr_tmp=$(mktemp -t audit_stderr.XXXXXX 2>/dev/null)
        _common_register_tmp "$stderr_tmp"
        if "$@" 2>"${stderr_tmp:-/dev/null}"; then
            rm -f "$stderr_tmp" 2>/dev/null
            return 0
        fi
        local code=$?
        local msg
        msg=$(_soft_capture_stderr_msg "$stderr_tmp")
        record_soft_failure "soft_probe_check:${probe}:$*"
        emit_probe_failed "$probe" "$code" "${1:-}" "" "$msg"
        rm -f "$stderr_tmp" 2>/dev/null
        return $code
    fi
    if "$@" 2>/dev/null; then
        return 0
    else
        local code=$?
        record_soft_failure "soft_probe_check:${probe}:$*"
        emit_probe_failed "$probe" "$code" "${1:-}"
        return $code
    fi
}

sum_bytes_from_stdin() {
    local total=0
    local f
    local b
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        b=$(stat_bytes "$f")
        b=${b:-0}
        total=$((total + b))
    done
    echo "$total"
}

emit_top_items_ndjson() {
    [ -n "$NDJSON_FILE" ] || return 0
    local event_type="$1"
    local source_file="$2"
    local limit="${3:-10}"
    local items_json=""
    local count=0
    local bytes
    local path

    [ -f "$source_file" ] || return 0
    while IFS=$'\t' read -r bytes path; do
        [ -n "$path" ] || continue
        ndjson_path=$(redact_path_for_ndjson "$path")
        path_json=$(json_escape "$ndjson_path")
        if (( count == 0 )); then
            items_json="{\"path\":$path_json,\"bytes\":${bytes:-0}}"
        else
            items_json="${items_json},{\"path\":$path_json,\"bytes\":${bytes:-0}}"
        fi
        count=$((count + 1))
    done < <(sort -nr -k1,1 "$source_file" | sed -n "1,${limit}p")

    if (( count > 0 )); then
        append_ndjson_line "{\"type\":$(json_escape "$event_type"),\"run_id\":$(json_escape "$RUN_ID"),\"items\":[${items_json}]}"
    fi
}

sanitize_run_id_for_filename() {
    local input="$1"
    local sanitized
    sanitized=$(printf '%s' "$input" | tr -c '[:alnum:]_.-' '_' | sed 's/^[._]*//; s/[._]*$//')
    [ -n "$sanitized" ] || sanitized="run"
    echo "$sanitized"
}
