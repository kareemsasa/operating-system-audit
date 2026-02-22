#!/usr/bin/env bash

if [[ "${_COMMON_SH_LOADED:-0}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi
_COMMON_SH_LOADED=1

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

soft() {
    "$@" 2>/dev/null || {
        record_soft_failure "soft:$*"
        return 0
    }
}

soft_out() {
    "$@" 2>/dev/null || {
        record_soft_failure "soft_out:$*"
        return 0
    }
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
