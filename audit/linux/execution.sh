#!/usr/bin/env bash
# =============================================================================
# Linux Execution & Processes Audit
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
# 🏃 Linux Execution & Processes Audit
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
    append_ndjson_line "{\"type\":\"meta\",\"run_id\":$(json_escape "$RUN_ID"),\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"execution-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO"),\"path\":$(json_escape "$(get_audit_path_for_output)")}"
    EXECUTION_NDJSON_INITIALIZED=true
}

run_execution_audit() {
    local total_processes=0
    local running_services=0
    local cron_jobs_count=0
    local user_services_count=0
    local user_timers_count=0

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
    done < <(soft_out_probe "execution.ps_aux" ps aux | awk 'NR==1{next} {cmd=$11; for(i=12;i<=NF;i++) cmd=cmd " " $i; printf "%s\t%s\t%s\t%s\t%s\n",$2,$1,$3,$4,cmd}' | sort -t$'\t' -k3,3nr | sed -n '1,15p')
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
    done < <(soft_out_probe "execution.ps_aux" ps aux | awk 'NR==1{next} {cmd=$11; for(i=12;i<=NF;i++) cmd=cmd " " $i; printf "%s\t%s\t%s\t%s\t%s\n",$2,$1,$3,$4,cmd}' | sort -t$'\t' -k4,4nr | sed -n '1,15p')
    append_ndjson_line "{\"type\":\"top_processes_mem\",\"run_id\":$(json_escape "$RUN_ID"),\"items\":[${mem_items}]}"
    section_end_ms=$(now_ms)
    emit_timing "top_processes_mem" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "📅 Scheduled Tasks"

    # User cron
    cron_raw="$(soft_out_probe "execution.crontab_l" crontab -l 2>/dev/null)"
    if [ -n "$cron_raw" ]; then
        cron_jobs_count=$(echo "$cron_raw" | awk 'NF && $1 !~ /^#/ {c++} END{print c+0}')
    else
        cron_jobs_count=0
    fi
    echo "- User cron jobs: **${cron_jobs_count:-0}**" >> "$REPORT_FILE"

    # System cron dirs
    local sys_cron_count=0
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$crondir" ]; then
            dir_count=$(find "$crondir" -type f ! -name '.placeholder' 2>/dev/null | wc -l | tr -d ' ' || true)
            dir_count=${dir_count:-0}
            if (( dir_count > 0 )); then
                echo "- \`$crondir\`: **$dir_count** entries" >> "$REPORT_FILE"
                sys_cron_count=$((sys_cron_count + dir_count))
            fi
        fi
    done
    if [ -f /etc/crontab ]; then
        etc_cron_lines=$(awk 'NF && $1 !~ /^#/ && $1 !~ /^[A-Z]/' /etc/crontab 2>/dev/null | wc -l | tr -d ' ' || true)
        echo "- \`/etc/crontab\` entries: **${etc_cron_lines:-0}**" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"

    # Systemd user services
    echo "User systemd services:" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    if command -v systemctl >/dev/null 2>&1; then
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            unit="$(echo "$line" | awk '{print $1}')"
            state="$(echo "$line" | awk '{print $2}')"
            [ -n "$unit" ] || continue
            echo "- \`$unit\` — $state" >> "$REPORT_FILE"
            user_services_count=$((user_services_count + 1))
        done < <(systemctl --user list-unit-files --type=service --no-pager --no-legend 2>/dev/null | awk '$2 == "enabled" || $2 == "static" {print}' | sed -n '1,20p')
    fi
    if (( user_services_count == 0 )); then
        echo "- _No user services found._" >> "$REPORT_FILE"
    fi

    append_ndjson_line "{\"type\":\"scheduled_tasks\",\"run_id\":$(json_escape "$RUN_ID"),\"cron_jobs\":${cron_jobs_count:-0},\"sys_cron_entries\":${sys_cron_count:-0},\"user_services\":${user_services_count:-0}}"
    section_end_ms=$(now_ms)
    emit_timing "scheduled_tasks" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "⏲️ Systemd Timers"
    echo "| Timer | Next Run | Unit |" >> "$REPORT_FILE"
    echo "|-------|----------|------|" >> "$REPORT_FILE"
    local timers_count=0
    if command -v systemctl >/dev/null 2>&1; then
        while IFS=$'\t' read -r next_run timer_unit activates; do
            [ -n "$timer_unit" ] || continue
            echo "| \`$timer_unit\` | $next_run | \`$activates\` |" >> "$REPORT_FILE"
            timers_count=$((timers_count + 1))
        done < <(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{
            next_run = $1 " " $2 " " $3 " " $4 " " $5
            timer = $(NF-1)
            activates = $NF
            printf "%s\t%s\t%s\n", next_run, timer, activates
        }' | sed -n '1,20p')

        # Also user timers
        while IFS=$'\t' read -r next_run timer_unit activates; do
            [ -n "$timer_unit" ] || continue
            echo "| \`$timer_unit\` (user) | $next_run | \`$activates\` |" >> "$REPORT_FILE"
            user_timers_count=$((user_timers_count + 1))
            timers_count=$((timers_count + 1))
        done < <(systemctl --user list-timers --all --no-pager --no-legend 2>/dev/null | awk '{
            next_run = $1 " " $2 " " $3 " " $4 " " $5
            timer = $(NF-1)
            activates = $NF
            printf "%s\t%s\t%s\n", next_run, timer, activates
        }' | sed -n '1,20p')
    fi
    if (( timers_count == 0 )); then
        echo "_No active timers found._" >> "$REPORT_FILE"
    fi
    append_ndjson_line "{\"type\":\"systemd_timers\",\"run_id\":$(json_escape "$RUN_ID"),\"system_timers\":$((timers_count - user_timers_count)),\"user_timers\":${user_timers_count:-0}}"
    section_end_ms=$(now_ms)
    emit_timing "systemd_timers" "$section_start_ms" "$section_end_ms"

    section_start_ms=$(now_ms)
    section_header "🧾 Process/Daemon Summary"
    total_processes="$(soft_out_probe "execution.ps_aux" ps aux | awk 'NR>1 {c++} END{print c+0}')"
    total_processes="${total_processes:-0}"
    if command -v systemctl >/dev/null 2>&1; then
        running_services="$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | wc -l | tr -d ' ' || true)"
    fi
    running_services="${running_services:-0}"
    echo "- Total running processes: **$total_processes**" >> "$REPORT_FILE"
    echo "- Running systemd services: **$running_services**" >> "$REPORT_FILE"
    append_ndjson_line "{\"type\":\"execution_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"total_processes\":${total_processes:-0},\"running_services\":${running_services:-0},\"cron_jobs\":${cron_jobs_count:-0},\"user_services\":${user_services_count:-0}}"
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
    emit_probe_failures_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    execution_main "$@"
fi
