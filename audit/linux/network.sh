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
    cat > "$REPORT_FILE" << EOF
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
    NETWORK_NDJSON_INITIALIZED=true
}

run_network_audit() {
    local interfaces_count=0
    local listening_count=0
    local established_count=0
    local firewall_enabled=false
    local firewall_backend="unknown"

    section_start_ms=$(now_ms)
    section_header "🔌 Active Network Interfaces"
    echo "| Interface | IP | Status |" >> "$REPORT_FILE"
    echo "|-----------|----|--------|" >> "$REPORT_FILE"
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
            echo "| \`$iface\` | $ip | $status |" >> "$REPORT_FILE"
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
            echo "| \`$iface\` | $ip | $status |" >> "$REPORT_FILE"
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
        echo "_No interfaces discovered._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"network_interfaces\",\"run_id\":$(json_escape "$RUN_ID"),\"items\":[${interfaces_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "network_interfaces" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🎧 Listening TCP Ports"
    echo "| Process | PID | Port |" >> "$REPORT_FILE"
    echo "|---------|-----|------|" >> "$REPORT_FILE"
    local listening_items=""
    if command -v ss >/dev/null 2>&1; then
        while IFS=$'\t' read -r pname pid port; do
            [ -n "$port" ] || continue
            echo "| \`$pname\` | $pid | $port |" >> "$REPORT_FILE"
            item="{\"process\":$(json_escape "$pname"),\"pid\":${pid:-0},\"port\":${port:-0}}"
            if [ -z "$listening_items" ]; then
                listening_items="$item"
            else
                listening_items="${listening_items},${item}"
            fi
            listening_count=$((listening_count + 1))
        done < <(soft_out_probe "network.ss_listen" ss -tlnp 2>/dev/null | awk 'NR>1 {
            port=$4; sub(/.*:/,"",port)
            proc=$7; gsub(/.*users:\(\("/,"",proc); gsub(/".*/,"",proc)
            pid=$7; gsub(/.*pid=/,"",pid); gsub(/,.*/,"",pid)
            if (port ~ /^[0-9]+$/) printf "%s\t%s\t%s\n", proc, pid, port
        }' | sed -n '1,20p')
    fi
    if (( listening_count == 0 )); then
        echo "_No listening TCP ports discovered (or probe unavailable)._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"listening_ports\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${listening_count:-0},\"items\":[${listening_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "listening_ports" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧭 DNS Configuration"
    echo "Configured DNS servers:" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    local dns_count=0
    if command -v resolvectl >/dev/null 2>&1; then
        while IFS= read -r dns; do
            [ -n "$dns" ] || continue
            echo "- \`$dns\`" >> "$REPORT_FILE"
            dns_count=$((dns_count + 1))
        done < <(soft_out_probe "network.resolvectl_dns" resolvectl dns 2>/dev/null | awk '{for(i=2;i<=NF;i++) print $i}' | sort -u || true)
    fi
    if (( dns_count == 0 )) && [ -f /etc/resolv.conf ]; then
        while IFS= read -r dns; do
            [ -n "$dns" ] || continue
            echo "- \`$dns\`" >> "$REPORT_FILE"
            dns_count=$((dns_count + 1))
        done < <(awk '/^nameserver/ {print $2}' /etc/resolv.conf | sort -u || true)
    fi
    if (( dns_count == 0 )); then
        echo "_No DNS servers discovered._" >> "$REPORT_FILE"
    fi
    section_end_ms=$(now_ms)
    emit_timing "dns_configuration" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧱 Firewall Status"
    if command -v ufw >/dev/null 2>&1; then
        ufw_out="$(soft_out_probe "network.ufw_status" ufw status 2>/dev/null)"
        if echo "$ufw_out" | grep -qi "active"; then
            firewall_enabled=true
            firewall_backend="ufw"
        fi
    fi
    if [ "$firewall_backend" = "unknown" ] && command -v firewall-cmd >/dev/null 2>&1; then
        fw_state="$(soft_out_probe "network.firewalld_state" firewall-cmd --state 2>/dev/null)"
        if echo "$fw_state" | grep -qi "running"; then
            firewall_enabled=true
            firewall_backend="firewalld"
        fi
    fi
    if [ "$firewall_backend" = "unknown" ] && command -v nft >/dev/null 2>&1; then
        nft_out="$(soft_out_probe "network.nft_list" nft list ruleset 2>/dev/null)"
        if [ -n "$nft_out" ]; then
            firewall_enabled=true
            firewall_backend="nftables"
        fi
    fi
    if [ "$firewall_backend" = "unknown" ] && command -v iptables >/dev/null 2>&1; then
        ipt_rules="$(soft_out_probe "network.iptables_list" iptables -L -n 2>/dev/null | awk 'NR>2 {c++} END{print c+0}')"
        if [ "${ipt_rules:-0}" -gt 0 ] 2>/dev/null; then
            firewall_enabled=true
            firewall_backend="iptables"
        fi
    fi
    echo "- Firewall enabled: **$firewall_enabled**" >> "$REPORT_FILE"
    echo "- Firewall backend: **$firewall_backend**" >> "$REPORT_FILE"
    append_ndjson_line "{\"type\":\"firewall_status\",\"run_id\":$(json_escape "$RUN_ID"),\"enabled\":$firewall_enabled,\"backend\":$(json_escape "$firewall_backend")}"
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
    echo "- Established TCP connections: **$established_count**" >> "$REPORT_FILE"
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
    echo "- SSID: \`$ssid\`" >> "$REPORT_FILE"
    echo "- BSSID: \`$bssid\`" >> "$REPORT_FILE"
    section_end_ms=$(now_ms)
    emit_timing "wifi_info" "$section_start_ms" "$section_end_ms"

    append_ndjson_line "{\"type\":\"network_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"interfaces\":${interfaces_count:-0},\"listening_ports\":${listening_count:-0},\"established_connections\":${established_count:-0}}"
}

network_main() {
    network_set_defaults_if_unset
    network_parse_args "$@"
    network_validate_and_resolve_paths
    network_prepare_files_and_common
    network_write_report_header_if_needed
    network_init_ndjson_if_needed
    run_network_audit
    emit_probe_failures_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    network_main "$@"
fi
