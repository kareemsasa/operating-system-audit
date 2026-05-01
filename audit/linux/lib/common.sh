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
    _common_require_var_set "REDACT_ALL" || return 1
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

# Keep binary path, drop all arguments. Use for process command lines.
# Example: "/opt/brave-bin/brave --type=renderer --crashpad-handler-pid=7400 ..." -> "/opt/brave-bin/brave <args>"
redact_command() {
    local s="$1"
    if [[ "$s" != *" "* ]]; then
        echo "$s"
        return
    fi
    local first="${s%% *}"
    echo "${first} <args>"
}

# Append text to report file. When REDACT_ALL, text is redacted. Use for all report output.
# Usage: report_append "line"
#        report_append -e "\n## Section\n"   # interpret backslash escapes
report_append() {
    if [[ "${1:-}" == "-e" ]]; then
        shift
        printf '%b\n' "$*" | maybe_redact_all_text >> "$REPORT_FILE"
    else
        printf '%s\n' "$*" | maybe_redact_all_text >> "$REPORT_FILE"
    fi
}

# Overwrite report file with stdin. When REDACT_ALL, content is redacted.
# Usage: cat << EOF | report_write
report_write() {
    maybe_redact_all_text > "$REPORT_FILE"
}

# Pipeline helper: redact when REDACT_ALL, else pass through. Use in pipes: ... | maybe_redact_all_text | ...
maybe_redact_all_text() {
    if [[ "${REDACT_ALL:-false}" == "true" ]]; then
        redact_all_text
    else
        cat
    fi
}

# Apply all redaction layers when REDACT_ALL is true. Use for arbitrary text output.
# When called with no args in a pipeline, reads from stdin.
redact_all_text() {
    local s
    if [[ $# -gt 0 ]]; then
        s="$1"
    else
        s="$(cat)"
    fi
    if ! _common_is_true "$REDACT_ALL"; then
        echo "$s"
        return
    fi
    # Order: user, hostname, home, then token patterns, then command truncation
    s=$(echo "$s" | sed -e "s#${HOME_DIR}#~#g" \
        -e "s#${CURRENT_USER}#<user>#g" \
        -e "s#${HOSTNAME_VAL}#<hostname>#g")
    # SSH fingerprints
    s=$(echo "$s" | sed -E 's/SHA256:[A-Za-z0-9+/=]+/SHA256:<redacted>/g')
    # Long hex strings (32+ chars)
    s=$(echo "$s" | sed -E 's/[A-Fa-f0-9]{32,}/<redacted>/g')
    # Base64 blobs (20+ chars after =)
    s=$(echo "$s" | sed -E 's/=([A-Za-z0-9+/=]{20,})/=<redacted>/g')
    # key=, token=, secret= values
    s=$(echo "$s" | sed -E 's/(key|token|secret)=[^[:space:]]+/\1=<redacted>/gi')
    # Process command lines (contains -- or starts with /)
    local line result=""
    while IFS= read -r line; do
        if [[ "$line" == *"--"* || "$line" == /* ]]; then
            result="${result}$(redact_command "$line")
"
        else
            result="${result}${line}
"
        fi
    done <<< "$s"
    echo -n "${result%$'\n'}"
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
    report_append -e "\n## $1\n"
}

count_lines() {
    local n
    n=$(wc -l | tr -d ' ' || true)
    echo "${n:-0}"
}

filter_dns_server_tokens() {
    awk '
        function clean_token(t) {
            gsub(/^[\[,]+/, "", t)
            gsub(/[\],]+$/, "", t)
            return t
        }
        function is_ipv4(t) {
            return t ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/
        }
        function is_ipv6(t) {
            return t ~ /^[0-9A-Fa-f:.]+(%[A-Za-z0-9_.-]+)?$/ && t ~ /:/ && t !~ /:$/
        }
        {
            for (i = 1; i <= NF; i++) {
                token = clean_token($i)
                if (is_ipv4(token) || is_ipv6(token)) {
                    print token
                }
            }
        }
    '
}

parse_ss_listening_tcp() {
    awk '
        function port_from_local(local, p) {
            p = local
            if (p ~ /\]:[0-9]+$/) {
                sub(/^.*\]:/, "", p)
            } else {
                sub(/^.*:/, "", p)
            }
            return p
        }
        {
            port = port_from_local($4)
            if (port !~ /^[0-9]+$/) {
                next
            }

            proc = "unknown"
            pid = "0"
            for (i = 1; i <= NF; i++) {
                if ($i ~ /users:\(\(/) {
                    proc = $i
                    gsub(/.*users:\(\("/, "", proc)
                    gsub(/".*/, "", proc)

                    pid = $i
                    gsub(/.*pid=/, "", pid)
                    gsub(/,.*/, "", pid)
                }
            }
            if (pid !~ /^[0-9]+$/) {
                pid = "0"
            }
            printf "%s\t%s\t%s\n", proc, pid, port
        }
    '
}

_systemctl_any_enabled() {
    command -v systemctl >/dev/null 2>&1 || return 1
    local unit
    for unit in "$@"; do
        systemctl is-enabled --quiet "$unit" >/dev/null 2>&1 && return 0
    done
    return 1
}

_systemctl_any_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    local unit
    for unit in "$@"; do
        systemctl is-active --quiet "$unit" >/dev/null 2>&1 && return 0
    done
    return 1
}

_linux_firewall_record_backend() {
    local backend="$1"
    local service_enabled="$2"
    local service_active="$3"
    local rules_active="$4"

    if [ -z "${FIREWALL_BACKENDS:-}" ]; then
        FIREWALL_BACKENDS="$backend"
    else
        FIREWALL_BACKENDS="${FIREWALL_BACKENDS},${backend}"
    fi

    if [ "$service_enabled" = true ]; then FIREWALL_SERVICE_ENABLED=true; fi
    if [ "$service_active" = true ]; then FIREWALL_SERVICE_ACTIVE=true; fi
    if [ "$rules_active" = true ]; then FIREWALL_RULES_ACTIVE=true; fi

    local current_rank=0
    local candidate_rank=1
    [ "${FIREWALL_PRIMARY_SERVICE_ENABLED:-false}" = true ] && current_rank=2
    [ "${FIREWALL_PRIMARY_SERVICE_ACTIVE:-false}" = true ] && current_rank=3
    [ "${FIREWALL_PRIMARY_RULES_ACTIVE:-false}" = true ] && current_rank=4
    [ "$service_enabled" = true ] && candidate_rank=2
    [ "$service_active" = true ] && candidate_rank=3
    [ "$rules_active" = true ] && candidate_rank=4

    if [ "${FIREWALL_BACKEND:-unknown}" = "unknown" ] || [ "$candidate_rank" -gt "$current_rank" ]; then
        FIREWALL_BACKEND="$backend"
        FIREWALL_PRIMARY_SERVICE_ENABLED="$service_enabled"
        FIREWALL_PRIMARY_SERVICE_ACTIVE="$service_active"
        FIREWALL_PRIMARY_RULES_ACTIVE="$rules_active"
    fi
}

detect_linux_firewall_status() {
    local probe_prefix="${1:-linux}"
    FIREWALL_BACKEND="unknown"
    FIREWALL_BACKENDS=""
    FIREWALL_SERVICE_ENABLED=false
    FIREWALL_SERVICE_ACTIVE=false
    FIREWALL_RULES_ACTIVE=false
    FIREWALL_PRIMARY_SERVICE_ENABLED=false
    FIREWALL_PRIMARY_SERVICE_ACTIVE=false
    FIREWALL_PRIMARY_RULES_ACTIVE=false

    if command -v ufw >/dev/null 2>&1; then
        local ufw_out ufw_service_enabled=false ufw_service_active=false ufw_rules_active=false
        ufw_out="$(soft_out_probe "${probe_prefix}.ufw_status" ufw status 2>/dev/null)"
        _systemctl_any_enabled ufw ufw.service && ufw_service_enabled=true
        _systemctl_any_active ufw ufw.service && ufw_service_active=true
        echo "$ufw_out" | grep -Eqi '^Status:[[:space:]]+active' && ufw_rules_active=true
        _linux_firewall_record_backend "ufw" "$ufw_service_enabled" "$ufw_service_active" "$ufw_rules_active"
    fi

    if command -v firewall-cmd >/dev/null 2>&1; then
        local fw_state firewalld_service_enabled=false firewalld_service_active=false firewalld_rules_active=false
        fw_state="$(soft_out_probe "${probe_prefix}.firewalld_state" firewall-cmd --state 2>/dev/null)"
        _systemctl_any_enabled firewalld firewalld.service && firewalld_service_enabled=true
        if echo "$fw_state" | grep -qi "running"; then
            firewalld_service_active=true
            firewalld_rules_active=true
        elif _systemctl_any_active firewalld firewalld.service; then
            firewalld_service_active=true
        fi
        _linux_firewall_record_backend "firewalld" "$firewalld_service_enabled" "$firewalld_service_active" "$firewalld_rules_active"
    fi

    if command -v nft >/dev/null 2>&1; then
        local nft_out nft_service_enabled=false nft_service_active=false nft_rules_active=false
        nft_out="$(soft_out_probe "${probe_prefix}.nft_list" nft list ruleset 2>/dev/null)"
        _systemctl_any_enabled nftables nftables.service && nft_service_enabled=true
        _systemctl_any_active nftables nftables.service && nft_service_active=true
        [ -n "$nft_out" ] && nft_rules_active=true
        _linux_firewall_record_backend "nftables" "$nft_service_enabled" "$nft_service_active" "$nft_rules_active"
    fi

    if command -v iptables >/dev/null 2>&1; then
        local ipt_rules ip6t_rules iptables_service_enabled=false iptables_service_active=false iptables_rules_active=false
        ipt_rules="$(soft_out_probe "${probe_prefix}.iptables_rules" iptables -S 2>/dev/null | awk '$1 == "-A" {c++} END {print c+0}')"
        ip6t_rules=0
        if command -v ip6tables >/dev/null 2>&1; then
            ip6t_rules="$(soft_out_probe "${probe_prefix}.ip6tables_rules" ip6tables -S 2>/dev/null | awk '$1 == "-A" {c++} END {print c+0}')"
        fi
        _systemctl_any_enabled iptables iptables.service netfilter-persistent netfilter-persistent.service && iptables_service_enabled=true
        _systemctl_any_active iptables iptables.service netfilter-persistent netfilter-persistent.service && iptables_service_active=true
        if [ "${ipt_rules:-0}" -gt 0 ] 2>/dev/null || [ "${ip6t_rules:-0}" -gt 0 ] 2>/dev/null; then
            iptables_rules_active=true
        fi
        _linux_firewall_record_backend "iptables" "$iptables_service_enabled" "$iptables_service_active" "$iptables_rules_active"
    fi
}

emit_run_context() {
    [ -n "$NDJSON_FILE" ] || return 0
    local container=false
    local sandbox="host"
    local virt="none"
    local interactive=false
    local systemd_available=false
    local euid="${EUID:-$(id -u 2>/dev/null || echo 0)}"

    if [ -f /.dockerenv ]; then
        container=true
    fi
    if [ -r /proc/1/cgroup ] && grep -qaE '(docker|kubepods|containerd|libpod|lxc)' /proc/1/cgroup 2>/dev/null; then
        container=true
    fi
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt="$(systemd-detect-virt 2>/dev/null || true)"
        virt="${virt:-none}"
        if systemd-detect-virt --container --quiet >/dev/null 2>&1; then
            container=true
        fi
    fi
    if [ "$container" = true ]; then
        sandbox="container"
    elif [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${CODESPACES:-}" ] || [ -n "${OSAUDIT_SANDBOX:-}" ]; then
        sandbox="automation"
    fi
    if [ -t 0 ] && [ -t 1 ]; then
        interactive=true
    fi
    command -v systemctl >/dev/null 2>&1 && systemd_available=true

    append_ndjson_line "{\"type\":\"run_context\",\"run_id\":$(json_escape "$RUN_ID"),\"sandbox\":$(json_escape "$sandbox"),\"container\":$container,\"virt\":$(json_escape "$virt"),\"interactive\":$interactive,\"euid\":${euid:-0},\"user\":$(json_escape "$CURRENT_USER"),\"systemd_available\":$systemd_available}"
}

emit_soft_failure_warning_details() {
    local log_file="$1"
    local max_items="${2:-10}"
    [ -f "$log_file" ] || return 1

    local soft_failures
    soft_failures=$(wc -l < "$log_file" | tr -d ' ' || true)
    soft_failures=${soft_failures:-0}
    (( soft_failures > 0 )) || return 1

    report_append "- **Soft probe warnings:** $soft_failures"
    report_append ""
    report_append "### Soft Probe Warning Details"

    local details_json=""
    local count detail item_json
    while IFS=$'\t' read -r count detail; do
        [ -n "$detail" ] || continue
        report_append "- \`${detail}\` (${count}x)"
        item_json="{\"count\":${count:-0},\"detail\":$(json_escape "$detail")}"
        if [ -z "$details_json" ]; then
            details_json="$item_json"
        else
            details_json="${details_json},${item_json}"
        fi
    done < <(sort "$log_file" | uniq -c | sort -rn | sed -n "1,${max_items}p" | awk '{count=$1; sub(/^[[:space:]]*[0-9]+[[:space:]]+/, ""); print count "\t" substr($0, 1, 200)}')

    if [ -n "$NDJSON_FILE" ]; then
        append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"soft_failures\":${soft_failures:-0},\"details\":[${details_json}]}"
    fi
    return 0
}

emit_probe_failure_warning_details() {
    local pf_file="${1:-${PROBE_FAILURES_FILE:-$(dirname "$REPORT_FILE")/.probe-failures-$$.tmp}}"
    [ -f "$pf_file" ] || return 1

    local grouped_tmp
    grouped_tmp=$(mktemp -t audit_probe_warning_details.XXXXXX 2>/dev/null)
    _common_register_tmp "$grouped_tmp"

    awk -F '\t' '
        NF >= 3 && $1 != "" { counts[$1]++ }
        END {
            for (probe in counts) {
                print counts[probe] "\t" probe
            }
        }
    ' "$pf_file" | sort -t $'\t' -k2,2 > "$grouped_tmp"

    [ -s "$grouped_tmp" ] || return 1

    local soft_failures
    soft_failures=$(awk -F '\t' '{sum += $1} END {print sum + 0}' "$grouped_tmp")
    soft_failures=${soft_failures:-0}
    (( soft_failures > 0 )) || return 1

    report_append "- **Soft probe warnings:** $soft_failures"
    report_append ""
    report_append "### Soft Probe Warning Details"

    local details_json=""
    local count probe item_json
    while IFS=$'\t' read -r count probe; do
        [ -n "$probe" ] || continue
        report_append "- \`${probe}\` (${count}x)"
        item_json="{\"probe\":$(json_escape "$probe"),\"detail\":$(json_escape "$probe"),\"count\":${count:-0}}"
        if [ -z "$details_json" ]; then
            details_json="$item_json"
        else
            details_json="${details_json},${item_json}"
        fi
    done < "$grouped_tmp"

    if [ -n "$NDJSON_FILE" ]; then
        append_ndjson_line "{\"type\":\"warning\",\"run_id\":$(json_escape "$RUN_ID"),\"soft_failures\":${soft_failures:-0},\"details\":[${details_json}]}"
    fi
    return 0
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
