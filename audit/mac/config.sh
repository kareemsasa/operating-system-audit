#!/usr/bin/env bash
# =============================================================================
# Mac System Configuration Audit
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
  --no-color             Disable ANSI colors in terminal output
  -h, --help             Show this help and exit
EOF
}

config_set_defaults_if_unset() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_defaults_if_unset "config-audit" "config-audit"
}

config_parse_args() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_parse_args "config" config_usage "$@"
}

config_validate_and_resolve_paths() {
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
        REPORT_FILE="${REPORT_FILE:-$REPORT_DIR/config-audit-$TIMESTAMP_FOR_FILENAME.md}"
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
    cat > "$REPORT_FILE" << EOF
# ⚙️ Mac System Configuration Audit
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
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"config-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO")}"
    CONFIG_NDJSON_INITIALIZED=true
}

run_config_audit() {
    local filevault=false
    local sip=false
    local gatekeeper=false
    local firewall=false
    local homebrew_installed=false
    local profile_files_count=0

    section_start_ms=$(now_ms)
    section_header "🔐 Security Defaults"
    fv_status="$(soft_out fdesetup status)"
    if echo "$fv_status" | awk 'tolower($0) ~ /on/ {found=1} END{exit found ? 0 : 1}'; then
        filevault=true
    fi
    sip_status="$(soft_out csrutil status)"
    if echo "$sip_status" | awk 'tolower($0) ~ /enabled/ {found=1} END{exit found ? 0 : 1}'; then
        sip=true
    fi
    gk_status="$(soft_out spctl --status)"
    if echo "$gk_status" | awk 'tolower($0) ~ /enabled/ {found=1} END{exit found ? 0 : 1}'; then
        gatekeeper=true
    fi
    fw_global="$(soft_out defaults read /Library/Preferences/com.apple.alf globalstate | tr -d '[:space:]')"
    if [[ "$fw_global" =~ ^[0-9]+$ ]] && (( fw_global > 0 )); then
        firewall=true
    fi
    remote_login="$(soft_out systemsetup -getremotelogin)"
    remote_login="${remote_login:-Unavailable}"
    screen_lock_delay="$(soft_out defaults -currentHost read com.apple.screensaver askForPasswordDelay)"
    screen_lock_delay="${screen_lock_delay:-unset}"
    auto_updates="$(soft_out softwareupdate --schedule)"
    auto_updates="${auto_updates:-unknown}"
    echo "- FileVault enabled: **$filevault**" >> "$REPORT_FILE"
    echo "- SIP enabled: **$sip**" >> "$REPORT_FILE"
    echo "- Gatekeeper enabled: **$gatekeeper**" >> "$REPORT_FILE"
    echo "- Firewall enabled: **$firewall**" >> "$REPORT_FILE"
    echo "- Remote Login (SSH): \`$remote_login\`" >> "$REPORT_FILE"
    echo "- Screen lock delay: \`$screen_lock_delay\`" >> "$REPORT_FILE"
    echo "- Auto updates: \`$auto_updates\`" >> "$REPORT_FILE"
    append_ndjson_line "{\"type\":\"security_config\",\"run_id\":$(json_escape "$RUN_ID"),\"filevault\":$filevault,\"sip\":$sip,\"gatekeeper\":$gatekeeper,\"firewall\":$firewall}"
    section_end_ms=$(now_ms)
    emit_timing "security_defaults" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🌍 Environment Overview"
    path_value="${PATH:-}"
    if [ "${REDACT_PATHS:-false}" = true ]; then
        path_value="$(echo "$path_value" | sed "s#$HOME_DIR#~#g; s#/${CURRENT_USER}/#/<user>/#g")"
    fi
    echo "- PATH: \`$path_value\`" >> "$REPORT_FILE"
    echo "- SHELL: \`${SHELL:-unknown}\`" >> "$REPORT_FILE"
    echo "- LANG: \`${LANG:-unknown}\`" >> "$REPORT_FILE"
    echo "- TERM: \`${TERM:-unknown}\`" >> "$REPORT_FILE"
    section_end_ms=$(now_ms)
    emit_timing "environment_overview" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🍺 Homebrew Summary"
    brew_formulae=0
    brew_casks=0
    brew_prefix="not-installed"
    if command -v brew >/dev/null 2>&1; then
        homebrew_installed=true
        brew_prefix="$(soft_out brew --prefix)"
        brew_prefix="${brew_prefix:-unknown}"
        brew_formulae="$(soft_out brew list --formula | count_lines)"
        brew_casks="$(soft_out brew list --cask | count_lines)"
        brew_formulae="${brew_formulae:-0}"
        brew_casks="${brew_casks:-0}"
    fi
    echo "- Homebrew installed: **$homebrew_installed**" >> "$REPORT_FILE"
    echo "- Homebrew prefix: \`$brew_prefix\`" >> "$REPORT_FILE"
    echo "- Installed formulae: **${brew_formulae:-0}**" >> "$REPORT_FILE"
    echo "- Installed casks: **${brew_casks:-0}**" >> "$REPORT_FILE"
    append_ndjson_line "{\"type\":\"homebrew_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"installed\":$homebrew_installed,\"formulae\":${brew_formulae:-0},\"casks\":${brew_casks:-0}}"
    section_end_ms=$(now_ms)
    emit_timing "homebrew_summary" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "📄 Shell Profile Files"
    echo "Existing shell profile files:" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    for rc in "$HOME_DIR/.zshrc" "$HOME_DIR/.zprofile" "$HOME_DIR/.zshenv" "$HOME_DIR/.bashrc" "$HOME_DIR/.bash_profile" "$HOME_DIR/.profile"; do
        if [ -f "$rc" ]; then
            safe_rc="$(redact_path_for_ndjson "$rc")"
            echo "- \`$safe_rc\`" >> "$REPORT_FILE"
            profile_files_count=$((profile_files_count + 1))
        fi
    done
    if (( profile_files_count == 0 )); then
        echo "_No common profile files found._" >> "$REPORT_FILE"
    fi
    section_end_ms=$(now_ms)
    emit_timing "shell_profile_files" "$section_start_ms" "$section_end_ms"

    append_ndjson_line "{\"type\":\"config_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"shell\":$(json_escape "${SHELL:-unknown}"),\"profile_files\":${profile_files_count:-0},\"homebrew_installed\":$homebrew_installed}"
}

config_main() {
    config_set_defaults_if_unset
    config_parse_args "$@"
    config_validate_and_resolve_paths
    config_prepare_files_and_common
    config_write_report_header_if_needed
    config_init_ndjson_if_needed
    run_config_audit
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    config_main "$@"
fi
