#!/usr/bin/env bash
# =============================================================================
# Linux Network Audit
# Conservative mode — reports only, modifies NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

network_usage() {
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

network_set_defaults_if_unset() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_defaults_if_unset "network-audit"
}

network_parse_args() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_parse_args "network" network_usage "$@"
}

network_validate_and_resolve_paths() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_resolve_output_paths "network-audit"
}

network_prepare_files_and_common() {
    mkdir -p "$REPORT_DIR"
    SOFT_FAILURE_LOG="${SOFT_FAILURE_LOG:-$REPORT_DIR/.network-audit-soft-failures-$TIMESTAMP_FOR_FILENAME.log}"
    : > "$SOFT_FAILURE_LOG"

    source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
}

network_write_report_header_if_needed() {
    if [[ "${NETWORK_HEADER_READY:-false}" == "true" ]]; then
        return 0
    fi
    cat << EOF | report_write
# 🌐 Linux Network Audit
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
    NETWORK_HEADER_READY=true
}

network_init_ndjson_if_needed() {
    if [ -z "$NDJSON_FILE" ]; then
        return 0
    fi
    if [[ "${NETWORK_NDJSON_INITIALIZED:-false}" == "true" ]]; then
        return 0
    fi
    : > "$NDJSON_FILE"
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"network-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO"),\"path\":$(json_escape "$(get_audit_path_for_output)")}"
    emit_run_context
    NETWORK_NDJSON_INITIALIZED=true
}

run_network_audit() {
    local interfaces_count=0
    local listening_count=0
    local established_count=0
    local firewall_backend="unknown"
    local firewall_service_enabled=false
    local firewall_service_active=false
    local firewall_rules_active=false

    section_start_ms=$(now_ms)
    section_header "🔌 Active Network Interfaces"
    report_append "| Interface | IP | Status |"
    report_append "|-----------|----|--------|"
    local interfaces_items=""
    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            iface="$(echo "$line" | awk '{print $1}')"
            status="$(echo "$line" | awk '{print $2}')"
            ip="$(echo "$line" | awk '{print $3}')"
            [ -n "$iface" ] || continue
            case "$status" in
                UP|UNKNOWN) status="active" ;;
                DOWN) status="inactive" ;;
                *) status="$status" ;;
            esac
            ip="${ip:-none}"
            # Strip CIDR suffix
            ip="${ip%%/*}"
            report_append "| \`$iface\` | $ip | $status |"
            item="{\"name\":$(json_escape "$iface"),\"ip\":$(json_escape "$ip"),\"status\":$(json_escape "$status")}"
            if [ -z "$interfaces_items" ]; then
                interfaces_items="$item"
            else
                interfaces_items="${interfaces_items},${item}"
            fi
            interfaces_count=$((interfaces_count + 1))
        done < <(soft_out_probe "network.ip_brief_addr" ip -br addr show 2>/dev/null || true)
    elif command -v ifconfig >/dev/null 2>&1; then
        while IFS= read -r iface; do
            [ -n "$iface" ] || continue
            iface_info="$(soft_out_probe "network.ifconfig_iface" ifconfig "$iface")"
            ip="$(echo "$iface_info" | awk '/inet / && $2 != "127.0.0.1" {print $2; exit}')"
            ip="${ip:-none}"
            status="inactive"
            if echo "$iface_info" | grep -q "UP"; then
                status="active"
            fi
            report_append "| \`$iface\` | $ip | $status |"
            item="{\"name\":$(json_escape "$iface"),\"ip\":$(json_escape "$ip"),\"status\":$(json_escape "$status")}"
            if [ -z "$interfaces_items" ]; then
                interfaces_items="$item"
            else
                interfaces_items="${interfaces_items},${item}"
            fi
            interfaces_count=$((interfaces_count + 1))
        done < <(ifconfig -a 2>/dev/null | awk '/^[a-z]/ {print $1}' | tr -d ':' || true)
    fi
    if (( interfaces_count == 0 )); then
        report_append "_No interfaces discovered._"
    fi
    append_ndjson_line "{\"type\":\"network_interfaces\",\"run_id\":$(json_escape "$RUN_ID"),\"items\":[${interfaces_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "network_interfaces" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🎧 Listening TCP Ports"
    report_append "| Process | PID | Port |"
    report_append "|---------|-----|------|"
    local listening_items=""
    if command -v ss >/dev/null 2>&1; then
        local ss_out
        ss_out="$(soft_out_probe "network.ss_listen" ss -H -tlnp 2>/dev/null)"
        if [ -z "$ss_out" ]; then
            ss_out="$(soft_out_probe "network.ss_listen_no_header_fallback" ss -tlnp 2>/dev/null | awk 'NR>1')"
        fi
        if [ -z "$ss_out" ]; then
            ss_out="$(soft_out_probe "network.ss_listen_no_process" ss -H -tln 2>/dev/null)"
        fi
        while IFS=$'\t' read -r pname pid port; do
            [ -n "$port" ] || continue
            pname="${pname:-unknown}"
            pid="${pid:-0}"
            report_append "| \`$pname\` | $pid | $port |"
            item="{\"process\":$(json_escape "$pname"),\"pid\":${pid:-0},\"port\":${port:-0}}"
            if [ -z "$listening_items" ]; then
                listening_items="$item"
            else
                listening_items="${listening_items},${item}"
            fi
            listening_count=$((listening_count + 1))
        done < <(printf '%s\n' "$ss_out" | parse_ss_listening_tcp | sed -n '1,20p')
    fi
    if (( listening_count == 0 )); then
        report_append "_No listening TCP ports discovered (or probe unavailable)._"
    fi
    append_ndjson_line "{\"type\":\"listening_ports\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${listening_count:-0},\"items\":[${listening_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "listening_ports" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧭 DNS Configuration"
    report_append "Configured DNS servers:"
    report_append ""
    local dns_count=0
    if command -v resolvectl >/dev/null 2>&1; then
        while IFS= read -r dns; do
            [ -n "$dns" ] || continue
            report_append "- \`$dns\`"
            dns_count=$((dns_count + 1))
        done < <(soft_out_probe "network.resolvectl_dns" resolvectl dns 2>/dev/null | filter_dns_server_tokens | sort -u || true)
    fi
    if (( dns_count == 0 )) && [ -f /etc/resolv.conf ]; then
        while IFS= read -r dns; do
            [ -n "$dns" ] || continue
            report_append "- \`$dns\`"
            dns_count=$((dns_count + 1))
        done < <(awk '/^nameserver/ {print $2}' /etc/resolv.conf | sort -u || true)
    fi
    if (( dns_count == 0 )); then
        report_append "_No DNS servers discovered._"
    fi
    section_end_ms=$(now_ms)
    emit_timing "dns_configuration" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧱 Firewall Status"
    detect_linux_firewall_status "network"
    firewall_backend="$FIREWALL_BACKEND"
    firewall_service_enabled="$FIREWALL_SERVICE_ENABLED"
    firewall_service_active="$FIREWALL_SERVICE_ACTIVE"
    firewall_rules_active="$FIREWALL_RULES_ACTIVE"
    report_append "- Firewall service enabled: **$firewall_service_enabled**"
    report_append "- Firewall service active: **$firewall_service_active**"
    report_append "- Firewall rules active: **$firewall_rules_active**"
    report_append "- Firewall backend: **$firewall_backend**"
    append_ndjson_line "{\"type\":\"firewall_status\",\"run_id\":$(json_escape "$RUN_ID"),\"enabled\":$firewall_rules_active,\"service_enabled\":$firewall_service_enabled,\"service_active\":$firewall_service_active,\"rules_active\":$firewall_rules_active,\"backend\":$(json_escape "$firewall_backend"),\"backends\":$(json_escape "${FIREWALL_BACKENDS:-}")}"
    section_end_ms=$(now_ms)
    emit_timing "firewall_status" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🔗 Active Connections Summary"
    if command -v ss >/dev/null 2>&1; then
        established_count=$(ss -tn state established 2>/dev/null | awk 'NR>1 {c++} END{print c+0}' || true)
    else
        established_count=$(netstat -an 2>/dev/null | awk '/ESTABLISHED/ {c++} END{print c+0}' || true)
    fi
    established_count=${established_count:-0}
    report_append "- Established TCP connections: **$established_count**"
    section_end_ms=$(now_ms)
    emit_timing "active_connections" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "📶 Wi-Fi Information"
    local ssid="unknown"
    local bssid="unknown"
    if command -v nmcli >/dev/null 2>&1; then
        wifi_line="$(soft_out_probe "network.nmcli_wifi" nmcli -t -f active,ssid,bssid dev wifi 2>/dev/null | awk -F: '/^yes:/ {print; exit}')"
        if [ -n "$wifi_line" ]; then
            ssid="$(echo "$wifi_line" | cut -d: -f2)"
            bssid="$(echo "$wifi_line" | cut -d: -f3-)"
        fi
    elif command -v iwgetid >/dev/null 2>&1; then
        ssid="$(soft_out_probe "network.iwgetid_ssid" iwgetid -r 2>/dev/null)"
        bssid="$(soft_out_probe "network.iwgetid_bssid" iwgetid -ra 2>/dev/null)"
    fi
    ssid="${ssid:-unknown}"
    bssid="${bssid:-unknown}"
    report_append "- SSID: \`$ssid\`"
    report_append "- BSSID: \`$bssid\`"
    section_end_ms=$(now_ms)
    emit_timing "wifi_info" "$section_start_ms" "$section_end_ms"

    append_ndjson_line "{\"type\":\"network_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"interfaces\":${interfaces_count:-0},\"listening_ports\":${listening_count:-0},\"established_connections\":${established_count:-0}}"
}

network_main() {
    network_set_defaults_if_unset
    network_parse_args "$@"
    network_validate_and_resolve_paths
    network_prepare_files_and_common
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_run_meta_trap "network"
    network_write_report_header_if_needed
    network_init_ndjson_if_needed
    run_network_audit
    emit_probe_failures_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    network_main "$@"
fi
