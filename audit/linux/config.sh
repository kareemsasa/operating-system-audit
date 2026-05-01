#!/usr/bin/env bash
# =============================================================================
# Linux System Configuration Audit
# Conservative mode — reports only, modifies NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

config_usage() {
    cat << EOF
Usage: $(basename "${BASH_SOURCE[0]}") [options]

Options:
  --report-dir <path>    Output directory for Markdown report
  --output <path>        Exact Markdown output file path
  --ndjson               Also write a compact NDJSON summary file
  --redact-paths         Redact NDJSON paths (default: on when --ndjson)
  --no-redact-paths      Disable NDJSON path redaction (default off otherwise)
  --redact-all           Redact all sensitive text (implies --redact-paths)
  --no-color             Disable ANSI colors in terminal output
  -h, --help             Show this help and exit
EOF
}

config_set_defaults_if_unset() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_defaults_if_unset "config-audit"
}

config_parse_args() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_parse_args "config" config_usage "$@"
}

config_validate_and_resolve_paths() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_resolve_output_paths "config-audit"
}

config_prepare_files_and_common() {
    mkdir -p "$REPORT_DIR"
    SOFT_FAILURE_LOG="${SOFT_FAILURE_LOG:-$REPORT_DIR/.config-audit-soft-failures-$TIMESTAMP_FOR_FILENAME.log}"
    : > "$SOFT_FAILURE_LOG"

    source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
}

config_write_report_header_if_needed() {
    if [[ "${CONFIG_HEADER_READY:-false}" == "true" ]]; then
        return 0
    fi
    cat << EOF | report_write
# ⚙️ Linux System Configuration Audit
**Generated:** $(date "+%B %d, %Y at %I:%M %p")
**Home Directory:** $HOME_DIR
**Mode:** Conservative (report only — no system changes)

## Metadata
- **Timestamp (ISO-8601):** $ISO_TIMESTAMP
- **Run ID:** $RUN_ID
- **Hostname:** $HOSTNAME_VAL
- **Current user:** $CURRENT_USER
- **Distribution:** $OS_VERSION
- **Kernel:** \`$KERNEL_INFO\`

---

EOF
    CONFIG_HEADER_READY=true
}

config_init_ndjson_if_needed() {
    if [ -z "$NDJSON_FILE" ]; then
        return 0
    fi
    if [[ "${CONFIG_NDJSON_INITIALIZED:-false}" == "true" ]]; then
        return 0
    fi
    : > "$NDJSON_FILE"
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"config-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO"),\"path\":$(json_escape "$(get_audit_path_for_output)")}"
    emit_run_context
    CONFIG_NDJSON_INITIALIZED=true
}

run_config_audit() {
    local luks_encrypted=false
    local secure_boot=false
    local firewall=false
    local firewall_service_enabled=false
    local firewall_service_active=false
    local firewall_rules_active=false
    local mac_framework="none"
    local profile_files_count=0

    section_start_ms=$(now_ms)
    section_header "🔐 Security Defaults"

    # Disk encryption (LUKS)
    if command -v lsblk >/dev/null 2>&1; then
        luks_count=$(lsblk -o FSTYPE 2>/dev/null | grep -c 'crypto_LUKS' || true)
        crypt_count=$(lsblk -o TYPE 2>/dev/null | grep -c 'crypt' || true)
        if (( ${luks_count:-0} > 0 )) || (( ${crypt_count:-0} > 0 )); then
            luks_encrypted=true
        fi
    fi
    if ! $luks_encrypted && command -v dmsetup >/dev/null 2>&1; then
        dm_crypt="$(soft_out_probe "config.dmsetup_crypt" dmsetup ls --target crypt 2>/dev/null)"
        if [ -n "$dm_crypt" ] && [ "$dm_crypt" != "No devices found" ]; then
            luks_encrypted=true
        fi
    fi
    report_append "- Disk encryption (LUKS): **$luks_encrypted**"

    # Secure Boot
    if command -v mokutil >/dev/null 2>&1; then
        sb_out="$(soft_out_probe "config.mokutil_sb" mokutil --sb-state 2>/dev/null)"
        if echo "$sb_out" | grep -qi "SecureBoot enabled"; then
            secure_boot=true
        fi
    fi
    report_append "- Secure Boot: **$secure_boot**"

    # Firewall (separate service state from active rules)
    firewall_backend="unknown"
    detect_linux_firewall_status "config"
    firewall_backend="$FIREWALL_BACKEND"
    firewall_service_enabled="$FIREWALL_SERVICE_ENABLED"
    firewall_service_active="$FIREWALL_SERVICE_ACTIVE"
    firewall_rules_active="$FIREWALL_RULES_ACTIVE"
    firewall="$firewall_rules_active"
    report_append "- Firewall service enabled: **$firewall_service_enabled**"
    report_append "- Firewall service active: **$firewall_service_active**"
    report_append "- Firewall rules active: **$firewall_rules_active**"
    report_append "- Firewall backend: **$firewall_backend**"

    # SSH daemon
    sshd_active="unknown"
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
            sshd_active="active"
        else
            sshd_active="inactive"
        fi
    fi
    report_append "- SSH daemon: **$sshd_active**"

    # SELinux / AppArmor
    if command -v getenforce >/dev/null 2>&1; then
        se_mode="$(soft_out_probe "config.getenforce" getenforce 2>/dev/null)"
        se_mode="${se_mode:-unknown}"
        mac_framework="SELinux ($se_mode)"
    elif command -v aa-status >/dev/null 2>&1; then
        if aa-enabled 2>/dev/null | grep -qi "yes"; then
            aa_profiles="$(soft_out_probe "config.aa_status" aa-status --profiled 2>/dev/null)"
            mac_framework="AppArmor (${aa_profiles:-?} profiles)"
        else
            mac_framework="AppArmor (disabled)"
        fi
    fi
    report_append "- Mandatory access control: **$mac_framework**"

    # Auto updates
    auto_updates="unknown"
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
            auto_updates="unattended-upgrades (enabled)"
        elif systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
            auto_updates="dnf-automatic (enabled)"
        elif systemctl list-timers --all 2>/dev/null | grep -q "pacman\|paccache"; then
            auto_updates="pacman timer detected"
        else
            auto_updates="none detected"
        fi
    fi
    report_append "- Auto updates: **$auto_updates**"

    append_ndjson_line "{\"type\":\"security_config\",\"run_id\":$(json_escape "$RUN_ID"),\"luks_encrypted\":$luks_encrypted,\"secure_boot\":$secure_boot,\"firewall\":$firewall,\"firewall_service_enabled\":$firewall_service_enabled,\"firewall_service_active\":$firewall_service_active,\"firewall_rules_active\":$firewall_rules_active,\"firewall_backend\":$(json_escape "$firewall_backend"),\"firewall_backends\":$(json_escape "${FIREWALL_BACKENDS:-}"),\"mac_framework\":$(json_escape "$mac_framework")}"
    section_end_ms=$(now_ms)
    emit_timing "security_defaults" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🌍 Environment Overview"
    path_value="${PATH:-}"
    if [ "${REDACT_PATHS:-false}" = true ]; then
        path_value="$(echo "$path_value" | sed "s#$HOME_DIR#~#g; s#/${CURRENT_USER}/#/<user>/#g")"
    fi
    report_append "- PATH: \`$path_value\`"
    report_append "- SHELL: \`${SHELL:-unknown}\`"
    report_append "- LANG: \`${LANG:-unknown}\`"
    report_append "- TERM: \`${TERM:-unknown}\`"
    report_append "- XDG_SESSION_TYPE: \`${XDG_SESSION_TYPE:-unknown}\`"
    report_append "- XDG_CURRENT_DESKTOP: \`${XDG_CURRENT_DESKTOP:-unknown}\`"
    section_end_ms=$(now_ms)
    emit_timing "environment_overview" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "📦 Package Manager Summary"
    local pkg_managers_found=0
    if command -v pacman >/dev/null 2>&1; then
        pacman_count="$(pacman -Q 2>/dev/null | wc -l | tr -d ' ' || true)"
        report_append "- **pacman**: ${pacman_count:-0} packages"
        pkg_managers_found=$((pkg_managers_found + 1))
    fi
    if command -v dpkg >/dev/null 2>&1; then
        dpkg_count="$(dpkg --list 2>/dev/null | awk '/^ii/ {c++} END{print c+0}' || true)"
        report_append "- **dpkg**: ${dpkg_count:-0} packages"
        pkg_managers_found=$((pkg_managers_found + 1))
    fi
    if command -v rpm >/dev/null 2>&1 && ! command -v pacman >/dev/null 2>&1; then
        rpm_count="$(rpm -qa 2>/dev/null | wc -l | tr -d ' ' || true)"
        report_append "- **rpm**: ${rpm_count:-0} packages"
        pkg_managers_found=$((pkg_managers_found + 1))
    fi
    if command -v flatpak >/dev/null 2>&1; then
        flatpak_count="$(flatpak list 2>/dev/null | wc -l | tr -d ' ' || true)"
        report_append "- **flatpak**: ${flatpak_count:-0} packages"
        pkg_managers_found=$((pkg_managers_found + 1))
    fi
    if command -v snap >/dev/null 2>&1; then
        snap_count="$(snap list 2>/dev/null | awk 'NR>1 {c++} END{print c+0}' || true)"
        report_append "- **snap**: ${snap_count:-0} packages"
        pkg_managers_found=$((pkg_managers_found + 1))
    fi
    if command -v brew >/dev/null 2>&1; then
        brew_count="$(brew list --formula 2>/dev/null | wc -l | tr -d ' ' || true)"
        brew_cask_count="$(brew list --cask 2>/dev/null | wc -l | tr -d ' ' || true)"
        report_append "- **homebrew**: ${brew_count:-0} formulae, ${brew_cask_count:-0} casks"
        pkg_managers_found=$((pkg_managers_found + 1))
    fi
    if (( pkg_managers_found == 0 )); then
        report_append "_No supported package managers detected._"
    fi
    append_ndjson_line "{\"type\":\"package_manager_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"managers_found\":${pkg_managers_found}}"
    section_end_ms=$(now_ms)
    emit_timing "package_manager_summary" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "📄 Shell Profile Files"
    report_append "Existing shell profile files:"
    report_append ""
    for rc in "$HOME_DIR/.zshrc" "$HOME_DIR/.zprofile" "$HOME_DIR/.zshenv" "$HOME_DIR/.bashrc" "$HOME_DIR/.bash_profile" "$HOME_DIR/.profile" "$HOME_DIR/.config/fish/config.fish"; do
        if [ -f "$rc" ]; then
            safe_rc="$(redact_path_for_ndjson "$rc")"
            report_append "- \`$safe_rc\`"
            profile_files_count=$((profile_files_count + 1))
        fi
    done
    if (( profile_files_count == 0 )); then
        report_append "_No common profile files found._"
    fi
    section_end_ms=$(now_ms)
    emit_timing "shell_profile_files" "$section_start_ms" "$section_end_ms"

    append_ndjson_line "{\"type\":\"config_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"shell\":$(json_escape "${SHELL:-unknown}"),\"profile_files\":${profile_files_count:-0},\"luks_encrypted\":$luks_encrypted,\"secure_boot\":$secure_boot}"
}

config_main() {
    config_set_defaults_if_unset
    config_parse_args "$@"
    config_validate_and_resolve_paths
    config_prepare_files_and_common
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_run_meta_trap "config"
    config_write_report_header_if_needed
    config_init_ndjson_if_needed
    run_config_audit
    emit_probe_failures_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    config_main "$@"
fi
