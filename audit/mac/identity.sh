#!/usr/bin/env bash
# =============================================================================
# Mac Identity & Access Audit
# Conservative mode — reports only, modifies NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

identity_usage() {
    cat << EOF
Usage: $(basename "${BASH_SOURCE[0]}") [options]

Options:
  --report-dir <path>    Output directory for Markdown report
  --output <path>        Exact Markdown output file path
  --ndjson               Also write a compact NDJSON summary file
  --redact-paths         Redact NDJSON paths (default: on when --ndjson)
  --no-redact-paths      Disable NDJSON path redaction (default off otherwise)
  --no-color             Disable ANSI colors in terminal output
  -h, --help             Show this help and exit
EOF
}

identity_set_defaults_if_unset() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_defaults_if_unset "identity-audit" "identity-audit"
}

identity_parse_args() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_parse_args "identity" identity_usage "$@"
}

identity_validate_and_resolve_paths() {
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
        REPORT_FILE="${REPORT_FILE:-$REPORT_DIR/identity-audit-$TIMESTAMP_FOR_FILENAME.md}"
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

identity_prepare_files_and_common() {
    mkdir -p "$REPORT_DIR"
    SOFT_FAILURE_LOG="${SOFT_FAILURE_LOG:-$REPORT_DIR/.identity-audit-soft-failures-$TIMESTAMP_FOR_FILENAME.log}"
    : > "$SOFT_FAILURE_LOG"

    source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
}

identity_write_report_header_if_needed() {
    if [[ "${IDENTITY_HEADER_READY:-false}" == "true" ]]; then
        return 0
    fi
    cat > "$REPORT_FILE" << EOF
# 👤 Mac Identity & Access Audit
**Generated:** $(date "+%B %d, %Y at %I:%M %p")
**Home Directory:** $HOME_DIR
**Mode:** Conservative (report only — no system changes)

## Metadata
- **Timestamp (ISO-8601):** $ISO_TIMESTAMP
- **Run ID:** $RUN_ID
- **Hostname:** $HOSTNAME_VAL
- **Current user:** $CURRENT_USER
- **macOS product version:** $OS_VERSION
- **Kernel:** \`$KERNEL_INFO\`

---

EOF
    IDENTITY_HEADER_READY=true
}

identity_init_ndjson_if_needed() {
    if [ -z "$NDJSON_FILE" ]; then
        return 0
    fi
    if [[ "${IDENTITY_NDJSON_INITIALIZED:-false}" == "true" ]]; then
        return 0
    fi
    : > "$NDJSON_FILE"
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"identity-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO")}"
    IDENTITY_NDJSON_INITIALIZED=true
}

run_identity_audit() {
    local local_users_count=0
    local current_groups_count=0
    local ssh_keys_count=0
    local sudo_capable=false

    section_start_ms=$(now_ms)
    section_header "🧑 Local User Accounts"
    echo "| Username | UID | Admin |" >> "$REPORT_FILE"
    echo "|----------|-----|-------|" >> "$REPORT_FILE"
    local local_users_items=""
    while IFS= read -r username; do
        [ -n "$username" ] || continue
        case "$username" in
            _*) continue ;;
        esac
        uid="$(soft_out dscl . -read "/Users/$username" UniqueID | awk '/UniqueID:/ {print $2; exit}')"
        uid="${uid:-0}"
        admin=false
        if dseditgroup -o checkmember -m "$username" admin >/dev/null 2>&1; then
            admin=true
        fi
        echo "| \`$username\` | $uid | $admin |" >> "$REPORT_FILE"
        item="{\"username\":$(json_escape "$username"),\"uid\":${uid:-0},\"admin\":$admin}"
        if [ -z "$local_users_items" ]; then
            local_users_items="$item"
        else
            local_users_items="${local_users_items},${item}"
        fi
        local_users_count=$((local_users_count + 1))
    done < <(soft_out dscl . list /Users | sort)
    append_ndjson_line "{\"type\":\"local_users\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${local_users_count:-0},\"items\":[${local_users_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "local_users" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "👥 Current User Groups & Sudo"
    groups_line="$(id -Gn 2>/dev/null || groups "$(whoami)" 2>/dev/null || true)"
    groups_line="${groups_line:-unknown}"
    current_groups_count=$(echo "$groups_line" | awk '{print NF}')
    if echo "$groups_line" | awk '{for(i=1;i<=NF;i++) if($i=="admin" || $i=="wheel") found=1} END{exit found ? 0 : 1}'; then
        sudo_capable=true
    fi
    echo "- Current user: \`$CURRENT_USER\`" >> "$REPORT_FILE"
    echo "- Groups: \`$groups_line\`" >> "$REPORT_FILE"
    echo "- Sudo-capable (admin/wheel): **$sudo_capable**" >> "$REPORT_FILE"
    section_end_ms=$(now_ms)
    emit_timing "current_groups" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🔐 SSH Keys & SSH Configuration"
    local ssh_dir="$HOME_DIR/.ssh"
    local ssh_key_items=""
    echo "| Public Key File | Type | Fingerprint |" >> "$REPORT_FILE"
    echo "|-----------------|------|-------------|" >> "$REPORT_FILE"
    if [ -d "$ssh_dir" ]; then
        while IFS= read -r pubfile; do
            [ -n "$pubfile" ] || continue
            key_type="$(awk '{print $1; exit}' "$pubfile" 2>/dev/null || true)"
            key_type="${key_type:-unknown}"
            case "$key_type" in
                ssh-*) key_type="${key_type#ssh-}" ;;
                ecdsa-*) key_type="$key_type" ;;
            esac
            fingerprint="$(ssh-keygen -lf "$pubfile" 2>/dev/null | awk '{print $2; exit}' || true)"
            fingerprint="${fingerprint:-unknown}"
            safe_file="$(redact_path_for_ndjson "$pubfile")"
            echo "| \`$safe_file\` | $key_type | \`$fingerprint\` |" >> "$REPORT_FILE"
            item="{\"file\":$(json_escape "$safe_file"),\"type\":$(json_escape "$key_type"),\"fingerprint\":$(json_escape "$fingerprint")}"
            if [ -z "$ssh_key_items" ]; then
                ssh_key_items="$item"
            else
                ssh_key_items="${ssh_key_items},${item}"
            fi
            ssh_keys_count=$((ssh_keys_count + 1))
        done < <(ls "$ssh_dir"/*.pub 2>/dev/null || true)
    fi
    if (( ssh_keys_count == 0 )); then
        echo "_No public SSH keys found._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"ssh_keys\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${ssh_keys_count:-0},\"items\":[${ssh_key_items}]}"

    local auth_keys_count=0
    if [ -f "$ssh_dir/authorized_keys" ]; then
        auth_keys_count=$(awk 'NF && $1 !~ /^#/ {c++} END{print c+0}' "$ssh_dir/authorized_keys" 2>/dev/null || true)
    fi
    local ssh_hosts_count=0
    if [ -f "$ssh_dir/config" ]; then
        ssh_hosts_count=$(awk 'tolower($1)=="host" && $2 !~ /^\*/ {c++} END{print c+0}' "$ssh_dir/config" 2>/dev/null || true)
    fi
    echo "- \`authorized_keys\` entries: **${auth_keys_count:-0}**" >> "$REPORT_FILE"
    echo "- \`~/.ssh/config\` host entries: **${ssh_hosts_count:-0}**" >> "$REPORT_FILE"
    section_end_ms=$(now_ms)
    emit_timing "ssh_inventory" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🐚 Login Shell"
    shell_path="${SHELL:-unknown}"
    shell_valid=false
    if [ -f "/etc/shells" ] && awk -v s="$shell_path" '$0==s {found=1} END{exit found ? 0 : 1}' /etc/shells 2>/dev/null; then
        shell_valid=true
    fi
    echo "- Current shell: \`$shell_path\`" >> "$REPORT_FILE"
    echo "- Present in \`/etc/shells\`: **$shell_valid**" >> "$REPORT_FILE"
    section_end_ms=$(now_ms)
    emit_timing "login_shell" "$section_start_ms" "$section_end_ms"

    append_ndjson_line "{\"type\":\"identity_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"local_users\":${local_users_count:-0},\"current_groups\":${current_groups_count:-0},\"ssh_keys\":${ssh_keys_count:-0},\"sudo_capable\":$sudo_capable}"
}

identity_main() {
    identity_set_defaults_if_unset
    identity_parse_args "$@"
    identity_validate_and_resolve_paths
    identity_prepare_files_and_common
    identity_write_report_header_if_needed
    identity_init_ndjson_if_needed
    run_identity_audit
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    identity_main "$@"
fi
