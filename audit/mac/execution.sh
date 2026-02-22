#!/usr/bin/env bash
# =============================================================================
# Mac Execution & Processes Audit
# Conservative mode — reports only, modifies NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

execution_usage() {
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

execution_set_defaults_if_unset() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_set_defaults_if_unset "execution-audit"
}

execution_parse_args() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_parse_args "execution" execution_usage "$@"
}

execution_validate_and_resolve_paths() {
    source "$(dirname "${BASH_SOURCE[0]}")/lib/init.sh"
    audit_resolve_output_paths "execution-audit"
}

execution_prepare_files_and_common() {
    mkdir -p "$REPORT_DIR"
    SOFT_FAILURE_LOG="${SOFT_FAILURE_LOG:-$REPORT_DIR/.execution-audit-soft-failures-$TIMESTAMP_FOR_FILENAME.log}"
    : > "$SOFT_FAILURE_LOG"

    source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
}

execution_write_report_header_if_needed() {
    if [[ "${EXECUTION_HEADER_READY:-false}" == "true" ]]; then
        return 0
    fi
    cat > "$REPORT_FILE" << EOF
# 🏃 Mac Execution & Processes Audit
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
    EXECUTION_HEADER_READY=true
}

execution_init_ndjson_if_needed() {
    if [ -z "$NDJSON_FILE" ]; then
        return 0
    fi
    if [[ "${EXECUTION_NDJSON_INITIALIZED:-false}" == "true" ]]; then
        return 0
    fi
    : > "$NDJSON_FILE"
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"execution-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO")}"
    EXECUTION_NDJSON_INITIALIZED=true
}

run_execution_audit() {
    local total_processes=0
    local running_daemons=0
    local cron_jobs_count=0
    local user_launch_agents_count=0
    local login_items_count=0

    section_start_ms=$(now_ms)
    section_header "🔥 Top Processes by CPU"
    echo "| PID | User | CPU% | MEM% | Command |" >> "$REPORT_FILE"
    echo "|-----|------|------|------|---------|" >> "$REPORT_FILE"
    local cpu_items=""
    while IFS=$'\t' read -r pid user cpu mem command; do
        [ -n "$pid" ] || continue
        echo "| $pid | \`$user\` | $cpu | $mem | \`$command\` |" >> "$REPORT_FILE"
        item="{\"pid\":${pid:-0},\"user\":$(json_escape "$user"),\"cpu_pct\":${cpu:-0},\"command\":$(json_escape "$command")}"
        if [ -z "$cpu_items" ]; then
            cpu_items="$item"
        else
            cpu_items="${cpu_items},${item}"
        fi
    done < <(ps aux 2>/dev/null | awk 'NR==1{next} {cmd=$11; for(i=12;i<=NF;i++) cmd=cmd " " $i; printf "%s\t%s\t%s\t%s\t%s\n",$2,$1,$3,$4,cmd}' | sort -t$'\t' -k3,3nr | sed -n '1,15p')
    append_ndjson_line "{\"type\":\"top_processes_cpu\",\"run_id\":$(json_escape "$RUN_ID"),\"items\":[${cpu_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "top_processes_cpu" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧠 Top Processes by Memory"
    echo "| PID | User | MEM% | CPU% | Command |" >> "$REPORT_FILE"
    echo "|-----|------|------|------|---------|" >> "$REPORT_FILE"
    local mem_items=""
    while IFS=$'\t' read -r pid user cpu mem command; do
        [ -n "$pid" ] || continue
        echo "| $pid | \`$user\` | $mem | $cpu | \`$command\` |" >> "$REPORT_FILE"
        item="{\"pid\":${pid:-0},\"user\":$(json_escape "$user"),\"mem_pct\":${mem:-0},\"command\":$(json_escape "$command")}"
        if [ -z "$mem_items" ]; then
            mem_items="$item"
        else
            mem_items="${mem_items},${item}"
        fi
    done < <(ps aux 2>/dev/null | awk 'NR==1{next} {cmd=$11; for(i=12;i<=NF;i++) cmd=cmd " " $i; printf "%s\t%s\t%s\t%s\t%s\n",$2,$1,$3,$4,cmd}' | sort -t$'\t' -k4,4nr | sed -n '1,15p')
    append_ndjson_line "{\"type\":\"top_processes_mem\",\"run_id\":$(json_escape "$RUN_ID"),\"items\":[${mem_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "top_processes_mem" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "📅 Scheduled Tasks & Login Items"
    login_items_raw="$(soft_out osascript -e 'tell application "System Events" to get the name of every login item')"
    login_items_count=0
    if [ -n "$login_items_raw" ]; then
        login_items_count=$(echo "$login_items_raw" | awk -F',' '{print NF}')
        echo "- Login items: \`$login_items_raw\`" >> "$REPORT_FILE"
    else
        echo "- Login items: _none detected or unavailable_" >> "$REPORT_FILE"
    fi

    cron_raw="$(soft_out crontab -l)"
    if [ -n "$cron_raw" ]; then
        cron_jobs_count=$(echo "$cron_raw" | awk 'NF && $1 !~ /^#/ {c++} END{print c+0}')
    else
        cron_jobs_count=0
    fi
    echo "- User cron jobs: **${cron_jobs_count:-0}**" >> "$REPORT_FILE"

    echo "" >> "$REPORT_FILE"
    echo "User Launch Agents:" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    user_launch_agents_count=0
    shopt -s nullglob
    for plist in "$HOME_DIR"/Library/LaunchAgents/*.plist; do
        label="$(soft_out defaults read "$plist" Label)"
        label="${label:-$(basename "$plist")}"
        program="$(soft_out defaults read "$plist" Program)"
        if [ -z "$program" ]; then
            program="$(soft_out defaults read "$plist" ProgramArguments | awk 'NR==2 {gsub(/[ ;"]/,"",$0); print $0; exit}')"
        fi
        program="${program:-unknown}"
        safe_plist="$(redact_path_for_ndjson "$plist")"
        echo "- \`$safe_plist\` → label=\`$label\`, program=\`$program\`" >> "$REPORT_FILE"
        user_launch_agents_count=$((user_launch_agents_count + 1))
    done
    shopt -u nullglob
    if (( user_launch_agents_count == 0 )); then
        echo "- _No user LaunchAgents found._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"scheduled_tasks\",\"run_id\":$(json_escape "$RUN_ID"),\"cron_jobs\":${cron_jobs_count:-0},\"user_launch_agents\":${user_launch_agents_count:-0},\"login_items\":${login_items_count:-0}}"
    section_end_ms=$(now_ms)
    emit_timing "scheduled_tasks" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧾 Process/Daemon Summary"
    total_processes="$(ps aux 2>/dev/null | awk 'NR>1 {c++} END{print c+0}')"
    total_processes="${total_processes:-0}"
    running_daemons="$(soft_out launchctl list | awk 'NR>1 {c++} END{print c+0}')"
    running_daemons="${running_daemons:-0}"
    echo "- Total running processes: **$total_processes**" >> "$REPORT_FILE"
    echo "- Running launchctl entries: **$running_daemons**" >> "$REPORT_FILE"
    append_ndjson_line "{\"type\":\"execution_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"total_processes\":${total_processes:-0},\"running_daemons\":${running_daemons:-0},\"cron_jobs\":${cron_jobs_count:-0},\"user_launch_agents\":${user_launch_agents_count:-0}}"
    section_end_ms=$(now_ms)
    emit_timing "execution_summary" "$section_start_ms" "$section_end_ms"
}

execution_main() {
    execution_set_defaults_if_unset
    execution_parse_args "$@"
    execution_validate_and_resolve_paths
    execution_prepare_files_and_common
    execution_write_report_header_if_needed
    execution_init_ndjson_if_needed
    run_execution_audit
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    execution_main "$@"
fi
