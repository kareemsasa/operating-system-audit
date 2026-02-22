#!/usr/bin/env bash
# =============================================================================
# Mac Persistence Surfaces Audit
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
    audit_set_defaults_if_unset "persistence-audit" "persistence-audit"
}

persistence_parse_args() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_parse_args "persistence" persistence_usage "$@"
}

persistence_validate_and_resolve_paths() {
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
        REPORT_FILE="${REPORT_FILE:-$REPORT_DIR/persistence-audit-$TIMESTAMP_FOR_FILENAME.md}"
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
# 🧷 Mac Persistence Surfaces Audit
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
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"persistence-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO")}"
    PERSISTENCE_NDJSON_INITIALIZED=true
}

run_persistence_audit() {
    local system_daemons_count=0
    local system_agents_count=0
    local user_agents_count=0
    local third_party_kexts_count=0
    local login_hooks=false

    section_start_ms=$(now_ms)
    section_header "🧱 System Launch Daemons"
    echo "| Label | Program | File |" >> "$REPORT_FILE"
    echo "|-------|---------|------|" >> "$REPORT_FILE"
    local daemon_items=""
    shopt -s nullglob
    for plist in /Library/LaunchDaemons/*.plist; do
        label="$(soft_out defaults read "$plist" Label)"
        label="${label:-$(basename "$plist")}"
        program="$(soft_out defaults read "$plist" Program)"
        if [ -z "$program" ]; then
            program="$(soft_out defaults read "$plist" ProgramArguments | awk 'NR==2 {gsub(/[ ;"]/,"",$0); print $0; exit}')"
        fi
        program="${program:-unknown}"
        echo "| \`$label\` | \`$program\` | \`$plist\` |" >> "$REPORT_FILE"
        if (( system_daemons_count < 20 )); then
            item="{\"label\":$(json_escape "$label"),\"program\":$(json_escape "$program")}"
            if [ -z "$daemon_items" ]; then
                daemon_items="$item"
            else
                daemon_items="${daemon_items},${item}"
            fi
        fi
        system_daemons_count=$((system_daemons_count + 1))
    done
    shopt -u nullglob
    append_ndjson_line "{\"type\":\"launch_daemons\",\"run_id\":$(json_escape "$RUN_ID"),\"system_count\":${system_daemons_count:-0},\"items\":[${daemon_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "system_launch_daemons" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧬 Launch Agents (System + User)"
    echo "- System LaunchAgents:" >> "$REPORT_FILE"
    shopt -s nullglob
    for plist in /Library/LaunchAgents/*.plist; do
        echo "  - \`$plist\`" >> "$REPORT_FILE"
        system_agents_count=$((system_agents_count + 1))
    done
    echo "- User LaunchAgents:" >> "$REPORT_FILE"
    for plist in "$HOME_DIR"/Library/LaunchAgents/*.plist; do
        safe_plist="$(redact_path_for_ndjson "$plist")"
        echo "  - \`$safe_plist\`" >> "$REPORT_FILE"
        user_agents_count=$((user_agents_count + 1))
    done
    shopt -u nullglob
    if (( system_agents_count == 0 )); then
        echo "  - _none_" >> "$REPORT_FILE"
    fi
    if (( user_agents_count == 0 )); then
        echo "  - _none_" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"launch_agents\",\"run_id\":$(json_escape "$RUN_ID"),\"system_count\":${system_agents_count:-0},\"user_count\":${user_agents_count:-0}}"
    section_end_ms=$(now_ms)
    emit_timing "launch_agents" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧩 Kernel Extensions & System Extensions"
    local kext_items=""
    if command -v kmutil >/dev/null 2>&1; then
        while IFS=$'\t' read -r bundle_id version; do
            [ -n "$bundle_id" ] || continue
            case "$bundle_id" in
                com.apple.*) continue ;;
            esac
            item="{\"name\":$(json_escape "$bundle_id"),\"version\":$(json_escape "$version")}"
            if [ -z "$kext_items" ]; then
                kext_items="$item"
            else
                kext_items="${kext_items},${item}"
            fi
            third_party_kexts_count=$((third_party_kexts_count + 1))
        done < <(soft_out kmutil showloaded | awk 'NR>1 {print $7 "\t" $5}')
    else
        while IFS=$'\t' read -r bundle_id version; do
            [ -n "$bundle_id" ] || continue
            case "$bundle_id" in
                com.apple.*) continue ;;
            esac
            item="{\"name\":$(json_escape "$bundle_id"),\"version\":$(json_escape "$version")}"
            if [ -z "$kext_items" ]; then
                kext_items="$item"
            else
                kext_items="${kext_items},${item}"
            fi
            third_party_kexts_count=$((third_party_kexts_count + 1))
        done < <(soft_out kextstat | awk 'NR>1 {print $6 "\t" $4}')
    fi
    echo "- Third-party kernel extensions: **${third_party_kexts_count:-0}**" >> "$REPORT_FILE"
    sysext_out="$(soft_out systemextensionsctl list)"
    if [ -n "$sysext_out" ]; then
        echo "- System extensions output captured (best effort)." >> "$REPORT_FILE"
    else
        echo "- System extensions output unavailable (permissions or unsupported environment)." >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"kernel_extensions\",\"run_id\":$(json_escape "$RUN_ID"),\"third_party_count\":${third_party_kexts_count:-0},\"items\":[${kext_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "kernel_extensions" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🪝 Login Hooks & Authorization Plugins"
    login_hook="$(soft_out defaults read com.apple.loginwindow LoginHook)"
    logout_hook="$(soft_out defaults read com.apple.loginwindow LogoutHook)"
    if [ -n "${login_hook:-}" ] || [ -n "${logout_hook:-}" ]; then
        login_hooks=true
    fi
    echo "- LoginHook: \`${login_hook:-unset}\`" >> "$REPORT_FILE"
    echo "- LogoutHook: \`${logout_hook:-unset}\`" >> "$REPORT_FILE"
    if [ -d "/Library/Security/SecurityAgentPlugins" ]; then
        echo "- SecurityAgentPlugins:" >> "$REPORT_FILE"
        while IFS= read -r plugin; do
            [ -n "$plugin" ] || continue
            echo "  - \`$plugin\`" >> "$REPORT_FILE"
        done < <(ls /Library/Security/SecurityAgentPlugins 2>/dev/null || true)
    else
        echo "- SecurityAgentPlugins directory not present." >> "$REPORT_FILE"
    fi
    section_end_ms=$(now_ms)
    emit_timing "login_hooks_authorization_plugins" "$section_start_ms" "$section_end_ms"

    append_ndjson_line "{\"type\":\"persistence_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"system_daemons\":${system_daemons_count:-0},\"system_agents\":${system_agents_count:-0},\"user_agents\":${user_agents_count:-0},\"third_party_kexts\":${third_party_kexts_count:-0},\"login_hooks\":$login_hooks}"
}

persistence_main() {
    persistence_set_defaults_if_unset
    persistence_parse_args "$@"
    persistence_validate_and_resolve_paths
    persistence_prepare_files_and_common
    persistence_write_report_header_if_needed
    persistence_init_ndjson_if_needed
    run_persistence_audit
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    persistence_main "$@"
fi
