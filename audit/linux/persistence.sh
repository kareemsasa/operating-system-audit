#!/usr/bin/env bash
# =============================================================================
# Linux Persistence Surfaces Audit
# Conservative mode — reports only, modifies NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

persistence_usage() {
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

persistence_set_defaults_if_unset() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_defaults_if_unset "persistence-audit"
}

persistence_parse_args() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_parse_args "persistence" persistence_usage "$@"
}

persistence_validate_and_resolve_paths() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_resolve_output_paths "persistence-audit"
}

persistence_prepare_files_and_common() {
    mkdir -p "$REPORT_DIR"
    SOFT_FAILURE_LOG="${SOFT_FAILURE_LOG:-$REPORT_DIR/.persistence-audit-soft-failures-$TIMESTAMP_FOR_FILENAME.log}"
    : > "$SOFT_FAILURE_LOG"

    source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
}

persistence_write_report_header_if_needed() {
    if [[ "${PERSISTENCE_HEADER_READY:-false}" == "true" ]]; then
        return 0
    fi
    cat > "$REPORT_FILE" << EOF
# 🧷 Linux Persistence Surfaces Audit
**Generated:** $(date "+%B %d, %Y at %I:%M %p")
**Home Directory:** $HOME_DIR
**Mode:** Conservative (report only — no system changes)

## Metadata
- **Timestamp (ISO-8601):** $ISO_TIMESTAMP
- **Run ID:** $RUN_ID
- **Hostname:** $HOSTNAME_VAL
- **Current user:** $CURRENT_USER
- **Linux Distribution:** $OS_VERSION
- **Kernel:** \`$KERNEL_INFO\`

---

EOF
    PERSISTENCE_HEADER_READY=true
}

persistence_init_ndjson_if_needed() {
    if [ -z "$NDJSON_FILE" ]; then
        return 0
    fi
    if [[ "${PERSISTENCE_NDJSON_INITIALIZED:-false}" == "true" ]]; then
        return 0
    fi
    : > "$NDJSON_FILE"
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"persistence-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO"),\"path\":$(json_escape "$(get_audit_path_for_output)")}"
    PERSISTENCE_NDJSON_INITIALIZED=true
}

run_persistence_audit() {
    local enabled_services_count=0
    local user_services_count=0
    local kernel_modules_count=0
    local xdg_autostart_count=0
    local pam_non_default_count=0
    local init_d_count=0
    local rc_local_exists=false
    local rc_local_executable=false
    local dkms_count=0

    # -------------------------------------------------------------------------
    # Enabled System Services
    # -------------------------------------------------------------------------
    section_start_ms=$(now_ms)
    section_header "🔧 Enabled System Services"
    echo "| Unit | State |" >> "$REPORT_FILE"
    echo "|------|-------|" >> "$REPORT_FILE"
    local service_items=""
    if command -v systemctl >/dev/null 2>&1; then
        local line_count=0
        while IFS=$'\t' read -r unit state; do
            [ -n "$unit" ] || continue
            if (( line_count < 30 )); then
                echo "| \`$unit\` | $state |" >> "$REPORT_FILE"
                item="{\"unit\":$(json_escape "$unit"),\"state\":$(json_escape "$state")}"
                if [ -z "$service_items" ]; then
                    service_items="$item"
                else
                    service_items="${service_items},${item}"
                fi
            fi
            enabled_services_count=$((enabled_services_count + 1))
            line_count=$((line_count + 1))
        done < <(soft_out_probe "persistence.systemctl_enabled" systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | awk '{print $1 "\t" $2}')
    fi
    if (( enabled_services_count == 0 )); then
        echo "_No enabled system services found (systemctl unavailable or no enabled units)._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"enabled_services\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${enabled_services_count:-0},\"items\":[${service_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "enabled_services" "$section_start_ms" "$section_end_ms"

    # -------------------------------------------------------------------------
    # User Systemd Services
    # -------------------------------------------------------------------------
    section_start_ms=$(now_ms)
    section_header "👤 User Systemd Services"
    echo "| Unit | State |" >> "$REPORT_FILE"
    echo "|------|-------|" >> "$REPORT_FILE"
    local user_service_items=""
    if command -v systemctl >/dev/null 2>&1; then
        while IFS=$'\t' read -r unit state; do
            [ -n "$unit" ] || continue
            echo "| \`$unit\` | $state |" >> "$REPORT_FILE"
            item="{\"unit\":$(json_escape "$unit"),\"state\":$(json_escape "$state")}"
            if [ -z "$user_service_items" ]; then
                user_service_items="$item"
            else
                user_service_items="${user_service_items},${item}"
            fi
            user_services_count=$((user_services_count + 1))
        done < <(soft_out_probe "persistence.systemctl_user_services" systemctl --user list-unit-files --type=service --no-pager --no-legend 2>/dev/null | awk '$2 == "enabled" || $2 == "static" {print $1 "\t" $2}')
    fi
    if (( user_services_count == 0 )); then
        echo "_No user services found (systemctl unavailable or no enabled/static units)._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"user_services\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${user_services_count:-0},\"items\":[${user_service_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "user_services" "$section_start_ms" "$section_end_ms"

    # -------------------------------------------------------------------------
    # Loaded Kernel Modules
    # -------------------------------------------------------------------------
    section_start_ms=$(now_ms)
    section_header "🧩 Loaded Kernel Modules"
    echo "| Module | Size | Used by |" >> "$REPORT_FILE"
    echo "|--------|------|---------|" >> "$REPORT_FILE"
    local module_items=""
    while IFS=$'\t' read -r mod size used; do
        [ -n "$mod" ] || continue
        echo "| \`$mod\` | $size | $used |" >> "$REPORT_FILE"
        item="{\"module\":$(json_escape "$mod"),\"size\":$(json_escape "$size"),\"used_by\":$(json_escape "$used")}"
        if [ -z "$module_items" ]; then
            module_items="$item"
        else
            module_items="${module_items},${item}"
        fi
        kernel_modules_count=$((kernel_modules_count + 1))
    done < <(soft_out_probe "persistence.lsmod" lsmod 2>/dev/null | awk 'NR>1 {print $1 "\t" $2 "\t" $3}')
    if (( kernel_modules_count == 0 )); then
        echo "_No loaded kernel modules found._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"kernel_modules\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${kernel_modules_count:-0},\"items\":[${module_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "kernel_modules" "$section_start_ms" "$section_end_ms"

    # -------------------------------------------------------------------------
    # XDG Autostart Entries
    # -------------------------------------------------------------------------
    section_start_ms=$(now_ms)
    section_header "🪝 XDG Autostart Entries"
    local autostart_items=""
    shopt -s nullglob
    for desktop in "$HOME_DIR"/.config/autostart/*.desktop /etc/xdg/autostart/*.desktop; do
        [ -f "$desktop" ] || continue
        name=""
        if [ -r "$desktop" ]; then
            name="$(soft_out_probe "persistence.desktop_name" grep -E '^Name=' "$desktop" 2>/dev/null | head -1 | cut -d= -f2- | xargs)"
        fi
        name="${name:-$(basename "$desktop")}"
        safe_path="$(redact_path_for_ndjson "$desktop")"
        echo "- \`$safe_path\` — **$name**" >> "$REPORT_FILE"
        item="{\"path\":$(json_escape "$safe_path"),\"name\":$(json_escape "$name")}"
        if [ -z "$autostart_items" ]; then
            autostart_items="$item"
        else
            autostart_items="${autostart_items},${item}"
        fi
        xdg_autostart_count=$((xdg_autostart_count + 1))
    done
    shopt -u nullglob
    if (( xdg_autostart_count == 0 )); then
        echo "_No XDG autostart entries found._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"xdg_autostart\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${xdg_autostart_count:-0},\"items\":[${autostart_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "xdg_autostart" "$section_start_ms" "$section_end_ms"

    # -------------------------------------------------------------------------
    # PAM Configuration
    # -------------------------------------------------------------------------
    section_start_ms=$(now_ms)
    section_header "🔐 PAM Configuration"
    if [ -d /etc/pam.d ]; then
        # Common default PAM config names (from base pam package)
        local default_pam="other|common-auth|common-account|common-password|common-session|login|passwd|sshd|su|sudo|system-auth|chfn|chsh|runuser|runuser-l|remote|config-util|newusers|chpasswd|rlogin|rsh|su-l|system-local-login|system-login|system-remote-login|system-services"
        pam_non_default_count=$(soft_out_probe "persistence.pam_non_default" ls /etc/pam.d 2>/dev/null | grep -vE "^($default_pam)$" | wc -l | tr -d ' ' || true)
        pam_non_default_count=${pam_non_default_count:-0}
        echo "- Non-default PAM config files in \`/etc/pam.d/\`: **${pam_non_default_count}**" >> "$REPORT_FILE"
    else
        echo "- \`/etc/pam.d/\` directory not present." >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"pam_config\",\"run_id\":$(json_escape "$RUN_ID"),\"non_default_count\":${pam_non_default_count:-0}}"
    section_end_ms=$(now_ms)
    emit_timing "pam_config" "$section_start_ms" "$section_end_ms"

    # -------------------------------------------------------------------------
    # SysV Init Scripts
    # -------------------------------------------------------------------------
    section_start_ms=$(now_ms)
    section_header "📜 SysV Init Scripts"
    if [ -d /etc/init.d ]; then
        init_d_count=$(soft_out_probe "persistence.initd_list" ls /etc/init.d 2>/dev/null | wc -l | tr -d ' ' || true)
        init_d_count=${init_d_count:-0}
        echo "- Scripts in \`/etc/init.d/\`: **${init_d_count}**" >> "$REPORT_FILE"
        if (( init_d_count > 0 )) && (( init_d_count <= 30 )); then
            echo "" >> "$REPORT_FILE"
            while IFS= read -r script; do
                [ -n "$script" ] || continue
                echo "  - \`$script\`" >> "$REPORT_FILE"
            done < <(soft_out_probe "persistence.initd_list" ls /etc/init.d 2>/dev/null)
        fi
    else
        echo "- \`/etc/init.d/\` directory does not exist." >> "$REPORT_FILE"
    fi
    if [ -f /etc/rc.local ]; then
        rc_local_exists=true
        if [ -x /etc/rc.local ]; then
            rc_local_executable=true
        fi
        echo "- \`/etc/rc.local\`: exists, executable: **$rc_local_executable**" >> "$REPORT_FILE"
    else
        echo "- \`/etc/rc.local\`: not present" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"sysv_init\",\"run_id\":$(json_escape "$RUN_ID"),\"init_d_count\":${init_d_count:-0},\"rc_local_exists\":$rc_local_exists,\"rc_local_executable\":$rc_local_executable}"
    section_end_ms=$(now_ms)
    emit_timing "sysv_init" "$section_start_ms" "$section_end_ms"

    # -------------------------------------------------------------------------
    # DKMS Modules
    # -------------------------------------------------------------------------
    section_start_ms=$(now_ms)
    section_header "📦 DKMS Modules"
    if command -v dkms >/dev/null 2>&1; then
        dkms_out="$(soft_out_probe "persistence.dkms_status" dkms status 2>/dev/null)"
        if [ -n "$dkms_out" ]; then
            echo '```' >> "$REPORT_FILE"
            echo "$dkms_out" >> "$REPORT_FILE"
            echo '```' >> "$REPORT_FILE"
            dkms_count=$(echo "$dkms_out" | grep -c . || true)
            dkms_count=${dkms_count:-0}
        else
            echo "_No DKMS modules or dkms status returned empty._" >> "$REPORT_FILE"
        fi
    else
        echo "_dkms command not available._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"dkms_modules\",\"run_id\":$(json_escape "$RUN_ID"),\"output_lines\":${dkms_count:-0}}"
    section_end_ms=$(now_ms)
    emit_timing "dkms_modules" "$section_start_ms" "$section_end_ms"

    # -------------------------------------------------------------------------
    # Persistence Summary
    # -------------------------------------------------------------------------
    append_ndjson_line "{\"type\":\"persistence_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"enabled_services\":${enabled_services_count:-0},\"user_services\":${user_services_count:-0},\"loaded_modules\":${kernel_modules_count:-0},\"xdg_autostart_count\":${xdg_autostart_count:-0},\"pam_non_default_count\":${pam_non_default_count:-0},\"init_d_count\":${init_d_count:-0},\"rc_local_exists\":$rc_local_exists,\"rc_local_executable\":$rc_local_executable}"
}

persistence_main() {
    persistence_set_defaults_if_unset
    persistence_parse_args "$@"
    persistence_validate_and_resolve_paths
    persistence_prepare_files_and_common
    persistence_write_report_header_if_needed
    persistence_init_ndjson_if_needed
    run_persistence_audit
    emit_probe_failures_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    persistence_main "$@"
fi
