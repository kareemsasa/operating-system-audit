#!/usr/bin/env bash
# =============================================================================
# Mac Network Audit
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
    audit_set_defaults_if_unset "network-audit" "network-audit"
}

network_parse_args() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_parse_args "network" network_usage "$@"
}

network_validate_and_resolve_paths() {
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
        REPORT_FILE="${REPORT_FILE:-$REPORT_DIR/network-audit-$TIMESTAMP_FOR_FILENAME.md}"
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
# 🌐 Mac Network Audit
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
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"network-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO")}"
    NETWORK_NDJSON_INITIALIZED=true
}

run_network_audit() {
    local interfaces_count=0
    local listening_count=0
    local established_count=0
    local firewall_enabled=false
    local firewall_stealth=false

    section_start_ms=$(now_ms)
    section_header "🔌 Active Network Interfaces"
    echo "| Interface | IP | Status |" >> "$REPORT_FILE"
    echo "|-----------|----|--------|" >> "$REPORT_FILE"
    local interfaces_items=""
    while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        local iface_info
        iface_info="$(soft_out ifconfig "$iface")"
        local ip
        ip="$(echo "$iface_info" | awk '/inet / && $2 != "127.0.0.1" {print $2; exit}')"
        ip="${ip:-none}"
        local status="inactive"
        if echo "$iface_info" | awk '/status: active/ {found=1} END{exit found ? 0 : 1}'; then
            status="active"
        elif echo "$iface_info" | awk 'NR==1 && /<.*UP.*>/ {found=1} END{exit found ? 0 : 1}'; then
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
    done < <(ifconfig -l 2>/dev/null | tr ' ' '\n' || true)
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
    while IFS=$'\t' read -r pname pid port; do
        [ -n "$pid" ] || continue
        [ -n "$port" ] || continue
        echo "| \`$pname\` | $pid | $port |" >> "$REPORT_FILE"
        item="{\"process\":$(json_escape "$pname"),\"pid\":${pid:-0},\"port\":${port:-0}}"
        if [ -z "$listening_items" ]; then
            listening_items="$item"
        else
            listening_items="${listening_items},${item}"
        fi
        listening_count=$((listening_count + 1))
    done < <(soft_out lsof -iTCP -sTCP:LISTEN -nP | awk 'NR>1 {n=split($9,a,":"); p=a[n]; if (p ~ /^[0-9]+$/) printf "%s\t%s\t%s\n", $1, $2, p}' | sed -n '1,20p')
    if (( listening_count == 0 )); then
        echo "_No listening TCP ports discovered (or probe unavailable)._ " >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"listening_ports\",\"run_id\":$(json_escape "$RUN_ID"),\"count\":${listening_count:-0},\"items\":[${listening_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "listening_ports" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧭 DNS Configuration"
    echo "Configured DNS servers:" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    local dns_count=0
    while IFS= read -r dns; do
        [ -n "$dns" ] || continue
        echo "- \`$dns\`" >> "$REPORT_FILE"
        dns_count=$((dns_count + 1))
    done < <(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/ {print $3}' | sort -u || true)
    if (( dns_count == 0 )); then
        echo "_No DNS servers discovered._" >> "$REPORT_FILE"
    fi
    section_end_ms=$(now_ms)
    emit_timing "dns_configuration" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧱 Firewall Status"
    local fw_global
    fw_global="$(soft_out defaults read /Library/Preferences/com.apple.alf globalstate | tr -d '[:space:]')"
    if [[ "$fw_global" =~ ^[0-9]+$ ]] && (( fw_global > 0 )); then
        firewall_enabled=true
    fi
    local fw_stealth_out
    fw_stealth_out="$(soft_out /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode)"
    if echo "$fw_stealth_out" | awk 'tolower($0) ~ /enabled/ {found=1} END{exit found ? 0 : 1}'; then
        firewall_stealth=true
    fi
    echo "- Firewall enabled: **$firewall_enabled**" >> "$REPORT_FILE"
    echo "- Firewall stealth mode: **$firewall_stealth**" >> "$REPORT_FILE"
    append_ndjson_line "{\"type\":\"firewall_status\",\"run_id\":$(json_escape "$RUN_ID"),\"enabled\":$firewall_enabled,\"stealth\":$firewall_stealth}"
    section_end_ms=$(now_ms)
    emit_timing "firewall_status" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🔗 Active Connections Summary"
    established_count=$(netstat -an 2>/dev/null | awk '/ESTABLISHED/ {c++} END{print c+0}' || true)
    established_count=${established_count:-0}
    echo "- Established TCP connections: **$established_count**" >> "$REPORT_FILE"
    section_end_ms=$(now_ms)
    emit_timing "active_connections" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "📶 Wi-Fi Information"
    local airport_bin="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    local ssid="unknown"
    local bssid="unknown"
    if [ -x "$airport_bin" ]; then
        wifi_out="$(soft_out "$airport_bin" -I)"
        ssid="$(echo "$wifi_out" | awk -F': ' '/ SSID/ {print $2; exit}')"
        bssid="$(echo "$wifi_out" | awk -F': ' '/ BSSID/ {print $2; exit}')"
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
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    network_main "$@"
fi
