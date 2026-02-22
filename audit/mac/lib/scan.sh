#!/usr/bin/env bash
# =============================================================================
# Storage scan utilities and run_storage_audit
# Source after lib/common.sh. Expects HOME_DIR, SCAN_ROOTS, LARGE_FILE_THRESHOLD_MB,
# REPORT_FILE, NDJSON_FILE, etc. to be set by the caller.
# =============================================================================

if [[ "${_SCAN_SH_LOADED:-0}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi
_SCAN_SH_LOADED=1

scoped_find_pruned() {
    if [ -z "$ROOTS_OVERRIDE_RAW" ] && $DEEP_SCAN; then
        find "$HOME_DIR" \
            -type d \( -path "$HOME_DIR/Library" -o -path "$HOME_DIR/.Trash" -o -name "node_modules" -o -name ".git" \) -prune -o \
            "$@" -print 2>/dev/null || true
        return
    fi

    local root
    for root in "${SCAN_ROOTS[@]+"${SCAN_ROOTS[@]}"}"; do
        [ -e "$root" ] || continue
        find "$root" \
            -type d \( -name "node_modules" -o -name ".git" \) -prune -o \
            "$@" -print 2>/dev/null || true
    done
}

home_find_excluding() {
    find "$HOME_DIR" \
        -type d \( -path "$HOME_DIR/Library" -o -path "$HOME_DIR/.Trash" -o -name "node_modules" -o -name ".git" \) -prune -o \
        "$@" -print 2>/dev/null || true
}

human_size_kb() {
    local kb=${1:-0}
    if (( kb < 0 )); then
        kb=0
    fi

    if command -v numfmt >/dev/null 2>&1; then
        local bytes=$((kb * 1024))
        local nf
        nf=$(numfmt --to=iec --suffix=B "$bytes" 2>/dev/null || true)
        if [ -n "$nf" ]; then
            echo "${nf%B}"
            return 0
        fi
    fi

    if (( kb >= 1073741824 )); then
        echo "$((kb / 1073741824))T"
    elif (( kb >= 1048576 )); then
        echo "$((kb / 1048576))G"
    elif (( kb >= 1024 )); then
        echo "$((kb / 1024))M"
    else
        echo "${kb}K"
    fi
}

emit_large_files_bytes() {
    scoped_find_pruned -type f -size "+${LARGE_FILE_THRESHOLD_MB}M" | while IFS= read -r f; do
        [ -n "$f" ] || continue
        printf '%s\t%s\n' "$(stat_bytes "$f")" "$f"
    done | sort -nr -k1,1 -k2,2
}

# Appends Recommended Next Steps to REPORT_FILE only when relevant. Uses variables
# from run_storage_audit. Skips section entirely if nothing triggers.
emit_recommendations() {
    local trash_bytes=$((${OVERVIEW_KB_TRASH:-0} * 1024))
    local desktop_bytes=$((${OVERVIEW_KB_DESKTOP:-0} * 1024))
    local dl_threshold="${RECOMMENDATIONS_DL_THRESHOLD:-50}"
    local desktop_mb="${RECOMMENDATIONS_DESKTOP_MB:-50}"
    local desktop_threshold=$((desktop_mb * 1024 * 1024))
    local recs=()

    (( trash_bytes > 0 )) && recs+=("Empty Trash to reclaim $(human_size_kb $((trash_bytes / 1024)))")
    (( (${dmg_count:-0} + ${pkg_count:-0}) > 0 )) && recs+=("Delete installer artifacts (.dmg/.pkg)")
    (( ${old_dl_count:-0} > 0 )) && recs+=("Review ${old_dl_count} stale files in Downloads (older than ${OLD_FILE_DAYS:-180} days)")
    (( ${dl_file_count:-0} > dl_threshold )) && recs+=("Downloads has ${dl_file_count} files — consider triaging")
    (( desktop_bytes > desktop_threshold )) && recs+=("Desktop is $(human_size_kb $((desktop_bytes / 1024))) — move items to Documents")
    (( ${nm_count:-0} > 0 )) && recs+=("${nm_count} node_modules dirs found — run \`npx npkill\`")
    (( ${venv_count:-0} > 0 )) && recs+=("${venv_count} Python venvs found — remove unused ones")
    (( ${broken_links:-0} > 0 )) && recs+=("${broken_links} broken symlinks detected — review and remove")
    (( ${thumbs_count:-0} > 0 )) && recs+=("${thumbs_count} Windows artifacts found — safe to delete")
    (( ${large_count:-0} > 0 )) && recs+=("${large_count} files over ${LARGE_FILE_THRESHOLD_MB}MB — review for cleanup")

    (( ${#recs[@]} == 0 )) && return 0

    echo "" >> "$REPORT_FILE"
    echo "### Recommended Next Steps" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    local i=1
    for r in "${recs[@]}"; do
        echo "$i. $r" >> "$REPORT_FILE"
        (( i += 1 ))
    done
}

run_storage_audit() {
    ds_count=0
    dmg_count=0
    pkg_count=0
    zip_dl_count=0
    thumbs_db_count=0
    desktop_ini_count=0
    thumbs_count=0
    broken_links=0
    nm_count=0
    venv_count=0
    git_count=0
    venv_dirs_count=0
    pycache_dirs_count=0
    dup_found=0
    old_dl_count=0
    old_dl_bytes=0
    dl_file_count=0
    trash_count=0
    home_bytes=0

    # =============================================================================
    # 1. DISK USAGE OVERVIEW
    # =============================================================================
    section_start_ms=$(now_ms)
    section_header "📊 Disk Usage Overview"

    echo -e "Scanning home directory size..."

    echo "| Folder | Size |" >> "$REPORT_FILE"
    echo "|--------|------|" >> "$REPORT_FILE"

    OVERVIEW_KB_DOWNLOADS=0
    OVERVIEW_KB_DESKTOP=0
    OVERVIEW_KB_DOCUMENTS=0
    OVERVIEW_KB_TRASH=0
    total_kb=0
    folder_index=0
    while IFS=$'\t' read -r kb folder; do
        [ -n "$folder" ] || continue
        kb=${kb:-0}
        folder_name=$(basename "$folder")
        case "$folder_name" in
            Downloads) OVERVIEW_KB_DOWNLOADS=$kb ;;
            Desktop) OVERVIEW_KB_DESKTOP=$kb ;;
            Documents) OVERVIEW_KB_DOCUMENTS=$kb ;;
        esac
        folder_bytes=$((kb * 1024))
        total_kb=$((total_kb + kb))
        folder_ndjson_path=$(redact_path_for_ndjson "$folder")
        printf '%s\t%s\n' "$folder_bytes" "$folder_ndjson_path" >> "$TOP_PATHS_FILE"

        if (( folder_index >= 20 )); then
            continue
        fi
        size=$(human_size_kb "$kb")
        echo -e "  ${CYAN}$folder_name${NC}: $size"
        echo "| \`$folder_name\` | $size |" >> "$REPORT_FILE"
        folder_index=$((folder_index + 1))
    done < <(du -sk "$HOME_DIR"/*/ 2>/dev/null | sort -nr || true)

    # Capture dotdirs (e.g. .cursor, .vscode, .npm, .nvm) for overview and NDJSON reuse; .Trash done separately
    dotdir_kb=0
    while IFS=$'\t' read -r kb folder; do
        [ -n "$folder" ] || continue
        kb=${kb:-0}
        folder_name=$(basename "$folder")
        dotdir_kb=$((dotdir_kb + kb))
        folder_bytes=$((kb * 1024))
        folder_ndjson_path=$(redact_path_for_ndjson "$folder")
        printf '%s\t%s\n' "$folder_bytes" "$folder_ndjson_path" >> "$TOP_PATHS_FILE"
    done < <(du -sk "$HOME_DIR"/.??* 2>/dev/null | awk -v home="$HOME_DIR" -F'\t' '$2 != home "/.Trash" {print}' | sort -nr || true)
    total_kb=$((total_kb + dotdir_kb))

    # Add Trash to total and stash for NDJSON reuse (single du -sk)
    if [ -d "$HOME_DIR/.Trash" ]; then
        trash_kb=$(du -sk "$HOME_DIR/.Trash" 2>/dev/null | awk '{print $1}') || true
        trash_kb=${trash_kb:-0}
        OVERVIEW_KB_TRASH=$trash_kb
        total_kb=$((total_kb + trash_kb))
    fi

    if (( dotdir_kb > 0 )) && (( folder_index < 20 )); then
        echo -e "  ${CYAN}Hidden directories${NC}: $(human_size_kb "$dotdir_kb")"
        echo "| \`Hidden directories\` | $(human_size_kb "$dotdir_kb") |" >> "$REPORT_FILE"
    fi

    emit_top_items_ndjson "top_paths" "$TOP_PATHS_FILE" "$HEATMAP_EMIT_TOPN"

    total_size=$(human_size_kb "$total_kb")
    echo -e "\n  ${BOLD}Total home directory (visible directories only): $total_size${NC}"
    echo -e "\n**Total home directory size (visible directories only):** $total_size\n" >> "$REPORT_FILE"
    home_bytes=$((total_kb * 1024))
    section_end_ms=$(now_ms)
    emit_timing "disk_usage_overview" "$section_start_ms" "$section_end_ms"

    # =============================================================================
    # DOWNLOADS COMBINED SCAN (single find pass for Junk zip + Downloads section)
    # =============================================================================
    downloads_scan_start_ms=$(now_ms)
    dl_file_count=0
    old_dl_count=0
    old_dl_bytes=0
    zip_dl_count=0
    if [ -d "$HOME_DIR/Downloads" ]; then
        old_threshold_sec=$(($(date +%s) - (OLD_FILE_DAYS * 86400))) || true
        old_threshold_sec=${old_threshold_sec:-0}
        while IFS= read -r line; do
            case "$line" in
                dl_file_count:*) dl_file_count="${line#*:}" ;;
                old_dl_count:*) old_dl_count="${line#*:}" ;;
                old_dl_bytes:*) old_dl_bytes="${line#*:}" ;;
                zip_dl_count:*) zip_dl_count="${line#*:}" ;;
                ext:*)
                    rest="${line#*:}"
                    ext_name="${rest%%:*}"
                    rest="${rest#*:}"
                    ext_count="${rest%%:*}"
                    ext_bytes="${rest#*:}"
                    ext_name=$(echo "$ext_name" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
                    if [ -n "$ext_name" ]; then
                        eval "ext_${ext_name}_count=${ext_count:-0}"
                        eval "ext_${ext_name}_bytes=${ext_bytes:-0}"
                    fi
                    ;;
            esac
        done < <(
            find "$HOME_DIR/Downloads" -type f 2>/dev/null | while IFS= read -r f; do
                [ -n "$f" ] || continue
                bytes=$(stat -f%z "$f" 2>/dev/null || echo 0)
                atime=$(stat -f%a "$f" 2>/dev/null || echo 0)
                base=$(basename "$f")
                ext="${base##*.}"
                [[ "$ext" == "$base" ]] && ext=""
                ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
                printf '%s\t%s\t%s\n' "$bytes" "$atime" "$ext"
            done | awk -v old_thresh="$old_threshold_sec" '
                BEGIN { total=0; old_count=0; old_bytes=0; zip_count=0 }
                {
                    bytes=$1+0; atime=$2+0; ext=$3
                    total++
                    if (atime>0 && atime<old_thresh) { old_count++; old_bytes+=bytes }
                    ext_count[ext]++; ext_bytes[ext]+=bytes
                    if (ext=="zip") zip_count++
                }
                END {
                    print "dl_file_count:"total
                    print "old_dl_count:"old_count
                    print "old_dl_bytes:"old_bytes
                    print "zip_dl_count:"zip_count
                    for (e in ext_count) if (e!="") print "ext:"e":"ext_count[e]":"ext_bytes[e]
                }
            '
        ) || true
    fi
    dl_file_count=${dl_file_count:-0}
    old_dl_count=${old_dl_count:-0}
    old_dl_bytes=${old_dl_bytes:-0}
    zip_dl_count=${zip_dl_count:-0}
    downloads_scan_end_ms=$(now_ms)
    emit_timing "downloads_scan" "$downloads_scan_start_ms" "$downloads_scan_end_ms"

    # =============================================================================
    # 2. LARGE FILES (> threshold)
    # =============================================================================
    section_start_ms=$(now_ms)
    section_header "📦 Large Files (> ${LARGE_FILE_THRESHOLD_MB}MB)"

    echo -e "Scanning for large files..."

    large_count=0
    large_ndjson_count=0
    echo "| Size | File |" >> "$REPORT_FILE"
    echo "|------|------|" >> "$REPORT_FILE"

    while IFS=$'\t' read -r bytes file; do
        [ -n "$file" ] || continue
        size=$(du -sh "$file" 2>/dev/null | cut -f1)
        rel_path="${file#$HOME_DIR/}"
        echo -e "  ${RED}$size${NC}  $rel_path"
        echo "| $size | \`$rel_path\` |" >> "$REPORT_FILE"
        ((large_count += 1))
        if [ -n "$NDJSON_FILE" ] && (( large_ndjson_count < 10 )); then
            ndjson_path=$(redact_path_for_ndjson "$file")
            append_ndjson_line "{\"type\":\"large_file\",\"run_id\":$(json_escape "$RUN_ID"),\"path\":$(json_escape "$ndjson_path"),\"bytes\":${bytes:-0}}"
            ((large_ndjson_count += 1))
        fi
    done < <(emit_large_files_bytes | sed -n '1,30p')

    if (( large_count == 0 )); then
        echo -e "  ${GREEN}No files found over ${LARGE_FILE_THRESHOLD_MB}MB${NC}"
        echo "_No files found over ${LARGE_FILE_THRESHOLD_MB}MB._" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
    section_end_ms=$(now_ms)
    emit_timing "large_files" "$section_start_ms" "$section_end_ms"

    # =============================================================================
    # 3. JUNK FILES
    # =============================================================================
    section_header "🗑️ Junk Files"

    echo -e "Scanning for common junk..."

    junk_scan_start_ms=$(now_ms)
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        base=$(basename "$path")
        if [ "$base" = ".DS_Store" ]; then
            ds_count=$((ds_count + 1))
        fi
        if [ "$base" = "Thumbs.db" ]; then
            thumbs_db_count=$((thumbs_db_count + 1))
        fi
        if [ "$base" = "desktop.ini" ]; then
            desktop_ini_count=$((desktop_ini_count + 1))
        fi
        if [ -L "$path" ] && [ ! -e "$path" ]; then
            broken_links=$((broken_links + 1))
        fi
    done < <(
        find "$HOME_DIR" \( -path "*/Library" -o -path "*/.Trash" \) -prune -o \( \
            -name ".DS_Store" -o \
            -name "Thumbs.db" -o \
            -name "desktop.ini" -o \
            -type l ! -exec test -e {} \; \
        \) -print 2>/dev/null || true
    )
    thumbs_count=$((thumbs_db_count + desktop_ini_count))
    junk_scan_end_ms=$(now_ms)
    emit_timing "junk_scan_combined" "$junk_scan_start_ms" "$junk_scan_end_ms"

    echo -e "  .DS_Store files: ${YELLOW}$ds_count${NC}"
    echo "- **\`.DS_Store\` files:** $ds_count" >> "$REPORT_FILE"

    installers_start_ms=$(now_ms)
    declare -a dmg_files=()
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        dmg_files+=("$f")
    done < <(scoped_find_pruned -type f -name "*.dmg" | sort)
    dmg_count=${#dmg_files[@]}
    echo -e "  .dmg installers: ${YELLOW}$dmg_count${NC}"
    echo "- **\`.dmg\` installers:** $dmg_count" >> "$REPORT_FILE"

    if (( dmg_count > 0 )); then
        echo "" >> "$REPORT_FILE"
        echo "  DMG files found:" >> "$REPORT_FILE"
        for f in "${dmg_files[@]}"; do
            rel="${f#$HOME_DIR/}"
            fsize=$(du -sh "$f" 2>/dev/null | cut -f1)
            echo -e "    ${CYAN}$fsize${NC}  $rel"
            echo "  - \`$rel\` ($fsize)" >> "$REPORT_FILE"
        done
        echo "" >> "$REPORT_FILE"
    fi

    pkg_count=$(scoped_find_pruned -type f -name "*.pkg" | count_lines) || true
    pkg_count=${pkg_count:-0}
    echo -e "  .pkg installers: ${YELLOW}$pkg_count${NC}"
    echo "- **\`.pkg\` installers:** $pkg_count" >> "$REPORT_FILE"

    if [ -d "$HOME_DIR/Downloads" ]; then
        zip_note=""
    else
        zip_dl_count=0
        zip_note="_Downloads folder not found; zip scan skipped._"
    fi
    echo -e "  .zip files in Downloads: ${YELLOW}$zip_dl_count${NC}"
    echo "- **\`.zip\` files in Downloads:** $zip_dl_count" >> "$REPORT_FILE"
    if [ -n "$zip_note" ]; then
        echo "  ${YELLOW}Downloads folder not found; zip scan skipped.${NC}"
        echo "$zip_note" >> "$REPORT_FILE"
    fi
    installers_end_ms=$(now_ms)
    emit_timing "installers" "$installers_start_ms" "$installers_end_ms"

    echo -e "  Windows artifacts (Thumbs.db, desktop.ini): ${YELLOW}$thumbs_count${NC}"
    echo "- **Windows artifacts:** $thumbs_count" >> "$REPORT_FILE"
    echo -e "  Broken symlinks: ${YELLOW}$broken_links${NC}"
    echo "- **Broken symlinks:** $broken_links" >> "$REPORT_FILE"

    echo "" >> "$REPORT_FILE"

    # =============================================================================
    # 4. DOWNLOADS AUDIT
    # =============================================================================
    section_header "📥 Downloads Folder Audit"

    if [ -d "$HOME_DIR/Downloads" ]; then
        dl_size=$(human_size_kb "${OVERVIEW_KB_DOWNLOADS:-0}")
        echo -e "  Total size: ${BOLD}$dl_size${NC} ($dl_file_count files)"
        echo "**Total size:** $dl_size ($dl_file_count files)" >> "$REPORT_FILE"

        echo -e "\n  ${CYAN}File type breakdown:${NC}"
        echo -e "\n### File Type Breakdown\n" >> "$REPORT_FILE"
        echo "| Type | Count | Total Size |" >> "$REPORT_FILE"
        echo "|------|-------|------------|" >> "$REPORT_FILE"

        for ext in pdf dmg zip pkg png jpg jpeg gif mp4 mov mp3 doc docx xls xlsx csv txt html js py sh; do
            eval "count=\${ext_${ext}_count:-0}"
            if (( count > 0 )); then
                eval "ext_bytes=\${ext_${ext}_bytes:-0}"
                ext_kb=$((ext_bytes / 1024))
                ext_size=$(human_size_kb "$ext_kb")
                echo -e "    .$ext: ${YELLOW}$count files${NC} ($ext_size)"
                echo "| \`.$ext\` | $count | $ext_size |" >> "$REPORT_FILE"
            fi
        done

        echo -e "\n  ${CYAN}Old files (not accessed in ${OLD_FILE_DAYS}+ days):${NC}"
        echo -e "    Count: ${YELLOW}$old_dl_count${NC}"
        echo -e "\n### Stale Downloads (${OLD_FILE_DAYS}+ days since last access)\n" >> "$REPORT_FILE"
        echo "**Count:** $old_dl_count files" >> "$REPORT_FILE"

        if (( old_dl_count > 0 )); then
            old_dl_kb=$((${old_dl_bytes:-0} / 1024))
            old_dl_size=$(human_size_kb "$old_dl_kb")
            echo -e "    Total size: ${YELLOW}$old_dl_size${NC}"
            echo "**Total size:** $old_dl_size" >> "$REPORT_FILE"
        fi
    else
        echo -e "  ${RED}Downloads folder not found${NC}"
        echo "_Downloads folder not found._" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"

    # =============================================================================
    # 5. DESKTOP AUDIT
    # =============================================================================
    section_header "🖥️ Desktop Audit"

    if [ -d "$HOME_DIR/Desktop" ]; then
        desktop_size=$(human_size_kb "${OVERVIEW_KB_DESKTOP:-0}")
        desktop_count=$({ find "$HOME_DIR/Desktop" -maxdepth 1 -not -name "." -not -name "cleanup-audit" 2>/dev/null || true; } | count_lines)
        desktop_count=${desktop_count:-0}
        echo -e "  Items on Desktop: ${BOLD}$desktop_count${NC} ($desktop_size)"
        echo "**Items on Desktop:** $desktop_count ($desktop_size)" >> "$REPORT_FILE"

        if (( desktop_count > 0 )); then
            echo -e "\n  ${CYAN}Desktop items:${NC}"
            echo -e "\n### Desktop Items\n" >> "$REPORT_FILE"
            while IFS= read -r item; do
                [ -z "$item" ] && continue
                name=$(basename "$item")
                [ "$name" = "cleanup-audit" ] && continue
                isize=$(du -sh "$item" 2>/dev/null | cut -f1)
                if [ -d "$item" ]; then
                    echo -e "    📁 $name ($isize)"
                    echo "- 📁 \`$name/\` ($isize)" >> "$REPORT_FILE"
                else
                    echo -e "    📄 $name ($isize)"
                    echo "- 📄 \`$name\` ($isize)" >> "$REPORT_FILE"
                fi
            done < <(find "$HOME_DIR/Desktop" -maxdepth 1 -not -name "." -not -path "$HOME_DIR/Desktop" 2>/dev/null | sort)
        fi
    else
        echo -e "  ${RED}Desktop folder not found${NC}"
        echo "_Desktop folder not found._" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"

    # =============================================================================
    # 6. DOCUMENTS AUDIT
    # =============================================================================
    section_header "📁 Documents Audit"

    if [ -d "$HOME_DIR/Documents" ]; then
        docs_size=$(human_size_kb "${OVERVIEW_KB_DOCUMENTS:-0}")
        docs_folder_count=$({ find "$HOME_DIR/Documents" -maxdepth 1 -type d -not -name "." -not -path "$HOME_DIR/Documents" 2>/dev/null || true; } | count_lines)
        docs_folder_count=${docs_folder_count:-0}
        docs_file_count=$({ find "$HOME_DIR/Documents" -maxdepth 1 -type f 2>/dev/null || true; } | count_lines)
        docs_file_count=${docs_file_count:-0}
        echo -e "  Total size: ${BOLD}$docs_size${NC}"
        echo -e "  Top-level: ${YELLOW}$docs_folder_count folders, $docs_file_count loose files${NC}"
        echo "**Total size:** $docs_size" >> "$REPORT_FILE"
        echo "**Top-level:** $docs_folder_count folders, $docs_file_count loose files" >> "$REPORT_FILE"

        echo -e "\n  ${CYAN}Top folders by size:${NC}"
        echo -e "\n### Top Folders by Size\n" >> "$REPORT_FILE"
        echo "| Folder | Size |" >> "$REPORT_FILE"
        echo "|--------|------|" >> "$REPORT_FILE"
        while IFS=$'\t' read -r kb folder; do
            [ -n "$folder" ] || continue
            kb=${kb:-0}
            folder_bytes=$((kb * 1024))
            fname=$(basename "$folder")
            size=$(human_size_kb "$kb")
            printf '%s\t%s\n' "$folder_bytes" "$folder" >> "$TOP_DOCUMENTS_FOLDERS_FILE"
            echo -e "    📁 $fname: $size"
            echo "| \`$fname\` | $size |" >> "$REPORT_FILE"
        done < <(du -sk "$HOME_DIR/Documents"/*/ 2>/dev/null | sort -nr -k1,1 | sed -n '1,15p')

        if (( docs_file_count > 0 )); then
            echo -e "\n  ${CYAN}Loose files in Documents root:${NC}"
            echo -e "\n### Loose Files in Documents Root\n" >> "$REPORT_FILE"
            while IFS= read -r f; do
                [ -z "$f" ] && continue
                fname=$(basename "$f")
                fsize=$(du -sh "$f" 2>/dev/null | cut -f1)
                echo -e "    📄 $fname ($fsize)"
                echo "- \`$fname\` ($fsize)" >> "$REPORT_FILE"
            done < <(find "$HOME_DIR/Documents" -maxdepth 1 -type f 2>/dev/null | sort | sed -n '1,30p')
        fi
    else
        echo -e "  ${RED}Documents folder not found${NC}"
        echo "_Documents folder not found._" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"

    # =============================================================================
    # 7. NODE_MODULES / DEV BLOAT
    # =============================================================================
    section_header "⚙️ Developer Bloat"

    echo -e "Scanning for node_modules, .venv, build artifacts..."

    node_modules_start_ms=$(now_ms)
    declare -a nm_dirs=()
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        nm_dirs+=("$d")
    done < <(find "$HOME_DIR" -maxdepth 6 -type d -name "node_modules" -not -path "*/Library/*" 2>/dev/null | sort)
    nm_count=${#nm_dirs[@]}
    echo -e "  node_modules directories: ${YELLOW}$nm_count${NC}"
    echo "### node_modules Directories: $nm_count" >> "$REPORT_FILE"
    node_modules_end_ms=$(now_ms)
    emit_timing "node_modules" "$node_modules_start_ms" "$node_modules_end_ms"

    if (( nm_count > 0 )); then
        echo "" >> "$REPORT_FILE"
        echo "| Location | Size |" >> "$REPORT_FILE"
        echo "|----------|------|" >> "$REPORT_FILE"
        for nm in "${nm_dirs[@]}"; do
            nm_kb=$(du -sk "$nm" 2>/dev/null | awk '{print $1}') || true
            nm_kb=${nm_kb:-0}
            nm_bytes=$((nm_kb * 1024))
            nm_size=$(human_size_kb "$nm_kb")
            printf '%s\t%s\n' "$nm_bytes" "$nm" >> "$TOP_NODE_MODULES_FILE"
            rel="${nm#$HOME_DIR/}"
            echo -e "    ${CYAN}$nm_size${NC}  $rel"
            echo "| \`$rel\` | $nm_size |" >> "$REPORT_FILE"
        done
        echo "" >> "$REPORT_FILE"
    fi

    venv_dirs_count=$({ find "$HOME_DIR" -maxdepth 5 -type d \( -name ".venv" -o -name "venv" \) -not -path "*/Library/*" 2>/dev/null || true; } | count_lines)
    venv_dirs_count=${venv_dirs_count:-0}
    pycache_dirs_count=$({ find "$HOME_DIR" -maxdepth 5 -type d -name "__pycache__" -not -path "*/Library/*" 2>/dev/null || true; } | count_lines)
    pycache_dirs_count=${pycache_dirs_count:-0}
    venv_count=$((venv_dirs_count + pycache_dirs_count))
    venv_count=${venv_count:-0}
    echo -e "  Python venvs / __pycache__: ${YELLOW}$venv_count${NC}"
    echo "### Python Virtual Envs / Cache: $venv_count" >> "$REPORT_FILE"

    git_start_ms=$(now_ms)
    git_count=$({ find "$HOME_DIR" -maxdepth 5 -type d -name ".git" -not -path "*/Library/*" 2>/dev/null || true; } | count_lines)
    git_count=${git_count:-0}
    echo -e "  Git repositories: ${YELLOW}$git_count${NC}"
    echo "### Git Repositories: $git_count" >> "$REPORT_FILE"
    git_end_ms=$(now_ms)
    emit_timing "git_repositories" "$git_start_ms" "$git_end_ms"

    echo "" >> "$REPORT_FILE"

    # =============================================================================
    # 8. DUPLICATE FILE DETECTION (basic, by name + size)
    # =============================================================================
    section_header "🔍 Potential Duplicate Files"

    echo -e "Scanning for potential duplicates (same name + same size)..."
    echo -e "_Checking Downloads, Desktop, and Documents for files with identical names and sizes._\n" >> "$REPORT_FILE"

    dup_found=0
    for dir in "$HOME_DIR/Downloads" "$HOME_DIR/Desktop" "$HOME_DIR/Documents"; do
        [ -d "$dir" ] || continue
        dir_name=$(basename "$dir")

        declare -a copies=()
        while IFS= read -r c; do
            [ -n "$c" ] || continue
            copies+=("$c")
        done < <(find "$dir" -type f \( -name "* ([0-9])*" -o -name "* copy*" -o -name "*-1.*" -o -name "*-2.*" \) 2>/dev/null | sort)
        copy_count=${#copies[@]}

        if (( copy_count > 0 )); then
            echo -e "\n  ${CYAN}$dir_name — possible copies:${NC}"
            echo "### $dir_name\n" >> "$REPORT_FILE"
            for c in "${copies[@]}"; do
                cname=$(basename "$c")
                csize=$(du -sh "$c" 2>/dev/null | cut -f1)
                echo -e "    ${YELLOW}$cname${NC} ($csize)"
                echo "- \`$cname\` ($csize)" >> "$REPORT_FILE"
                ((dup_found += 1))
            done
            echo "" >> "$REPORT_FILE"
        fi
    done

    if (( dup_found == 0 )); then
        echo -e "  ${GREEN}No obvious duplicates found${NC}"
        echo "_No obvious duplicates found._" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"

    # =============================================================================
    # 9. TRASH SIZE
    # =============================================================================
    trash_start_ms=$(now_ms)
    section_header "🗑️ Trash"

    TRASH_DIR="$HOME_DIR/.Trash"
    if [ -d "$TRASH_DIR" ]; then
        trash_kb=${OVERVIEW_KB_TRASH:-0}
        trash_size=$(human_size_kb "$trash_kb")
        trash_count="$(soft_out find "$TRASH_DIR" -mindepth 1 -maxdepth 1 | count_lines)"
        trash_count=${trash_count:-0}
        echo -e "  Trash size: ${BOLD}$trash_size${NC} ($trash_count files)"
        echo "**Trash size:** $trash_size ($trash_count files)" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "_Empty Trash in Finder to reclaim this space._" >> "$REPORT_FILE"
    else
        echo -e "  ${GREEN}Trash is empty${NC}"
        echo "_Trash is empty._" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"
    trash_end_ms=$(now_ms)
    emit_timing "trash" "$trash_start_ms" "$trash_end_ms"

    if [ -n "$NDJSON_FILE" ]; then
        downloads_bytes=$((${OVERVIEW_KB_DOWNLOADS:-0} * 1024))
        desktop_bytes=$((${OVERVIEW_KB_DESKTOP:-0} * 1024))
        documents_bytes=$((${OVERVIEW_KB_DOCUMENTS:-0} * 1024))
        trash_bytes=$((${OVERVIEW_KB_TRASH:-0} * 1024))
        append_ndjson_line "{\"type\":\"summary\",\"run_id\":$(json_escape "$RUN_ID"),\"home_bytes\":${home_bytes:-0},\"downloads_bytes\":${downloads_bytes:-0},\"desktop_bytes\":${desktop_bytes:-0},\"documents_bytes\":${documents_bytes:-0},\"trash_bytes\":${trash_bytes:-0}}"
        append_ndjson_line "{\"type\":\"counts\",\"run_id\":$(json_escape "$RUN_ID"),\"large_files\":${large_count:-0},\"ds_store\":${ds_count:-0},\"thumbs_db\":${thumbs_db_count:-0},\"desktop_ini\":${desktop_ini_count:-0},\"windows_artifacts\":${thumbs_count:-0},\"zip_downloads\":${zip_dl_count:-0},\"dmg\":${dmg_count:-0},\"pkg\":${pkg_count:-0},\"broken_symlinks\":${broken_links:-0},\"node_modules\":${nm_count:-0},\"venv_cache\":${venv_count:-0},\"venv_dirs\":${venv_dirs_count:-0},\"pycache_dirs\":${pycache_dirs_count:-0},\"git_repos\":${git_count:-0},\"potential_duplicates\":${dup_found:-0},\"downloads_stale\":${old_dl_count:-0}}"
        append_ndjson_line "{\"type\":\"junk_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"ds_store_count\":${ds_count:-0},\"dmg_count\":${dmg_count:-0},\"pkg_count\":${pkg_count:-0},\"zip_downloads_count\":${zip_dl_count:-0},\"windows_artifacts_count\":${thumbs_count:-0},\"broken_symlinks_count\":${broken_links:-0}}"
        append_ndjson_line "{\"type\":\"downloads_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"total_bytes\":${downloads_bytes:-0},\"file_count\":${dl_file_count:-0},\"old_file_count\":${old_dl_count:-0},\"old_total_bytes\":${old_dl_bytes:-0}}"
        append_ndjson_line "{\"type\":\"dev_bloat_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"node_modules_dirs\":${nm_count:-0},\"python_venvs\":${venv_count:-0},\"python_venv_dirs\":${venv_dirs_count:-0},\"pycache_dirs\":${pycache_dirs_count:-0},\"git_repos\":${git_count:-0}}"
        append_ndjson_line "{\"type\":\"trash_summary\",\"run_id\":$(json_escape "$RUN_ID"),\"total_bytes\":${trash_bytes:-0},\"file_count\":${trash_count:-0}}"
        emit_top_items_ndjson "top_node_modules" "$TOP_NODE_MODULES_FILE" 10
        emit_top_items_ndjson "top_documents_folders" "$TOP_DOCUMENTS_FOLDERS_FILE" 10
    fi
}
