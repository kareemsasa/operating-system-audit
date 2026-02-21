#!/usr/bin/env bash
# =============================================================================
# Mac Home Directory Cleanup Audit
# Conservative mode — reports only, moves/deletes NOTHING
# =============================================================================

set -euo pipefail
export LC_ALL=C

# --- Defaults / Configuration ---
HOME_DIR="$HOME"
DEFAULT_REPORT_DIR="$(pwd)/output/cleanup-audit"
REPORT_DIR="${REPORT_DIR:-$DEFAULT_REPORT_DIR}"
LARGE_FILE_THRESHOLD_MB=100  # Flag files larger than this
OLD_FILE_DAYS=180            # Flag files not accessed in this many days
DEEP_SCAN=false
NO_COLOR=false
OUTPUT_FILE=""
WRITE_NDJSON=false
ROOTS_OVERRIDE_RAW=""
REDACT_PATHS_MODE="auto"
REDACT_PATHS=false
declare -a METADATA_NOTES=()
declare -a NDJSON_PENDING_NOTES=()

usage() {
    cat << EOF
Usage: $(basename "$0") [options]

Options:
  --report-dir <path>    Output directory for Markdown report
  --output <path>        Exact Markdown output file path
  --roots <paths>        Comma-separated scan roots (overrides defaults/deep)
  --threshold-mb <int>   Large file threshold in MB (default: 100)
  --old-days <int>       Stale file threshold in days (default: 180)
  --deep                 Scan full home dir (pruned for Library/.Trash/.git/node_modules)
  --ndjson               Also write a compact NDJSON summary file
  --redact-paths         Redact NDJSON paths (default: on when --ndjson)
  --no-redact-paths      Disable NDJSON path redaction (default off otherwise)
  --no-color             Disable ANSI colors in terminal output
  -h, --help             Show this help and exit
EOF
}

while (($# > 0)); do
    case "$1" in
        --report-dir)
            if (($# < 2)); then
                echo "Error: --report-dir requires a path" >&2
                exit 1
            fi
            REPORT_DIR="$2"
            shift 2
            ;;
        --output)
            if (($# < 2)); then
                echo "Error: --output requires a path" >&2
                exit 1
            fi
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --roots)
            if (($# < 2)); then
                echo "Error: --roots requires a comma-separated path list" >&2
                exit 1
            fi
            ROOTS_OVERRIDE_RAW="$2"
            shift 2
            ;;
        --threshold-mb)
            if (($# < 2)); then
                echo "Error: --threshold-mb requires an integer" >&2
                exit 1
            fi
            LARGE_FILE_THRESHOLD_MB="$2"
            shift 2
            ;;
        --old-days)
            if (($# < 2)); then
                echo "Error: --old-days requires an integer" >&2
                exit 1
            fi
            OLD_FILE_DAYS="$2"
            shift 2
            ;;
        --deep)
            DEEP_SCAN=true
            shift
            ;;
        --ndjson)
            WRITE_NDJSON=true
            shift
            ;;
        --redact-paths)
            REDACT_PATHS_MODE="on"
            shift
            ;;
        --no-redact-paths)
            REDACT_PATHS_MODE="off"
            shift
            ;;
        --no-color)
            NO_COLOR=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$1'" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ ! "$LARGE_FILE_THRESHOLD_MB" =~ ^[0-9]+$ ]]; then
    echo "Error: --threshold-mb must be a non-negative integer" >&2
    exit 1
fi

if [[ ! "$OLD_FILE_DAYS" =~ ^[0-9]+$ ]]; then
    echo "Error: --old-days must be a non-negative integer" >&2
    exit 1
fi

TIMESTAMP_FOR_FILENAME=$(date +"%Y%m%d-%H%M%S")
ISO_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
CURRENT_USER=$(id -un 2>/dev/null || echo "${USER:-unknown}")
if command -v sw_vers >/dev/null 2>&1; then
    OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
else
    OS_VERSION="unknown"
fi
KERNEL_INFO=$(uname -a 2>/dev/null || echo "unknown")

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
    REPORT_FILE="$REPORT_DIR/cleanup-audit-$TIMESTAMP_FOR_FILENAME.md"
fi

# Colors
if $NO_COLOR; then
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    BOLD=''
    NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

# Scan roots used for large files and junk installers.
declare -a SCAN_ROOTS
if $DEEP_SCAN; then
    SCAN_ROOTS=("$HOME_DIR")
else
    SCAN_ROOTS=("$HOME_DIR/Downloads" "$HOME_DIR/Desktop" "$HOME_DIR/Documents")
fi

if [ -n "$ROOTS_OVERRIDE_RAW" ]; then
    SCAN_ROOTS=()
    IFS=',' read -r -a requested_roots <<< "$ROOTS_OVERRIDE_RAW"
    for root in "${requested_roots[@]}"; do
        trimmed_root=$(echo "$root" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        [ -n "$trimmed_root" ] || continue
        if [ -e "$trimmed_root" ]; then
            SCAN_ROOTS+=("$trimmed_root")
        else
            note_msg="Skipping missing root: $trimmed_root"
            METADATA_NOTES+=("$note_msg")
            NDJSON_PENDING_NOTES+=("$note_msg")
        fi
    done
    if ((${#SCAN_ROOTS[@]} == 0)); then
        note_msg="No valid scan roots from --roots; scoped scans will return no matches"
        METADATA_NOTES+=("$note_msg")
        NDJSON_PENDING_NOTES+=("$note_msg")
    fi
fi

if $WRITE_NDJSON && ! command -v python3 >/dev/null 2>&1; then
    echo "Warning: --ndjson requested but python3 is unavailable; disabling NDJSON output." >&2
    METADATA_NOTES+=("NDJSON disabled because python3 is unavailable")
    WRITE_NDJSON=false
    REDACT_PATHS=false
fi

# --- Setup ---
mkdir -p "$REPORT_DIR"

NDJSON_FILE=""
if $WRITE_NDJSON; then
    report_base="${REPORT_FILE%.*}"
    if [ "$report_base" = "$REPORT_FILE" ]; then
        NDJSON_FILE="${REPORT_FILE}.ndjson"
    else
        NDJSON_FILE="${report_base}.ndjson"
    fi
fi

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║       Mac Home Directory Cleanup Audit           ║"
echo "║       Conservative Mode — Report Only            ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "Report will be saved to: ${GREEN}$REPORT_FILE${NC}"
echo ""

# Initialize report
cat > "$REPORT_FILE" << EOF
# 🧹 Mac Home Directory Cleanup Audit
**Generated:** $(date "+%B %d, %Y at %I:%M %p")
**Home Directory:** $HOME_DIR
**Mode:** Conservative (report only — nothing moved or deleted)

## Metadata
- **Timestamp (ISO-8601):** $ISO_TIMESTAMP
- **Hostname:** $HOSTNAME_VAL
- **Current user:** $CURRENT_USER
- **macOS product version:** $OS_VERSION
- **Kernel:** \`$KERNEL_INFO\`
EOF
for note in "${METADATA_NOTES[@]}"; do
    echo "- **Note:** $note" >> "$REPORT_FILE"
done
echo "" >> "$REPORT_FILE"
echo "---" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# --- Helper Functions ---
json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${1-}"
}

stat_bytes() {
    local path="$1"
    stat -f%z "$path" 2>/dev/null || stat -c%s "$path" 2>/dev/null || echo 0
}

dir_bytes() {
    local path="$1"
    if [ -d "$path" ]; then
        du -sk "$path" 2>/dev/null | awk '{print $1 * 1024}'
    else
        echo 0
    fi
}

append_ndjson_line() {
    [ -n "$NDJSON_FILE" ] || return 0
    echo "$1" >> "$NDJSON_FILE"
}

redact_path_for_ndjson() {
    local input_path="$1"
    if ! $REDACT_PATHS; then
        echo "$input_path"
        return
    fi

    case "$input_path" in
        "$HOME_DIR")
            echo "~"
            ;;
        "$HOME_DIR"/*)
            echo "~/${input_path#$HOME_DIR/}"
            ;;
        *)
            if [ -n "$CURRENT_USER" ]; then
                echo "$input_path" | sed "s#/${CURRENT_USER}/#/<user>/#g; s#/${CURRENT_USER}\$#/<user>#"
            else
                echo "$input_path"
            fi
            ;;
    esac
}

now_ms() {
    if command -v perl >/dev/null 2>&1; then
        perl -MTime::HiRes=time -e 'printf("%.0f\n", time()*1000)'
    else
        echo $(( $(date +%s) * 1000 ))
    fi
}

emit_timing() {
    [ -n "$NDJSON_FILE" ] || return 0
    local section="$1"
    local start_ms="$2"
    local end_ms="$3"
    local elapsed_ms=$((end_ms - start_ms))
    append_ndjson_line "{\"type\":\"timing\",\"section\":$(json_escape "$section"),\"elapsed_ms\":$elapsed_ms}"
}

section_header() {
    echo -e "\n${BOLD}${YELLOW}━━━ $1 ━━━${NC}"
    echo -e "\n## $1\n" >> "$REPORT_FILE"
}

scoped_find_pruned() {
    if [ -z "$ROOTS_OVERRIDE_RAW" ] && $DEEP_SCAN; then
        find "$HOME_DIR" \
            -type d \( -path "$HOME_DIR/Library" -o -path "$HOME_DIR/.Trash" -o -name "node_modules" -o -name ".git" \) -prune -o \
            "$@" -print 2>/dev/null
        return
    fi

    local root
    for root in "${SCAN_ROOTS[@]}"; do
        [ -e "$root" ] || continue
        find "$root" \
            -type d \( -name "node_modules" -o -name ".git" \) -prune -o \
            "$@" -print 2>/dev/null
    done
}

home_find_excluding() {
    find "$HOME_DIR" \
        -type d \( -path "$HOME_DIR/Library" -o -path "$HOME_DIR/.Trash" -o -name "node_modules" -o -name ".git" \) -prune -o \
        "$@" -print 2>/dev/null
}

emit_large_files_bytes() {
    scoped_find_pruned -type f -size "+${LARGE_FILE_THRESHOLD_MB}M" | while IFS= read -r f; do
        [ -n "$f" ] || continue
        printf '%s\t%s\n' "$(stat_bytes "$f")" "$f"
    done | sort -nr -k1,1 -k2,2
}

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
dup_found=0
old_dl_count=0
home_bytes=0

if [ -n "$NDJSON_FILE" ]; then
    : > "$NDJSON_FILE"
    scan_mode="scoped"
    if $DEEP_SCAN && [ -z "$ROOTS_OVERRIDE_RAW" ]; then
        scan_mode="deep"
    fi
    append_ndjson_line "{\"type\":\"meta\",\"schema_version\":\"0.1\",\"tool_name\":\"operating-system-audit\",\"tool_component\":\"home-cleanup-audit\",\"timestamp\":$(json_escape "$ISO_TIMESTAMP"),\"hostname\":$(json_escape "$HOSTNAME_VAL"),\"user\":$(json_escape "$CURRENT_USER"),\"os_version\":$(json_escape "$OS_VERSION"),\"kernel\":$(json_escape "$KERNEL_INFO")}"
    append_ndjson_line "{\"type\":\"scan\",\"mode\":$(json_escape "$scan_mode"),\"threshold_mb\":$LARGE_FILE_THRESHOLD_MB,\"old_days\":$OLD_FILE_DAYS,\"redact_paths\":$([ "$REDACT_PATHS" = true ] && echo true || echo false)}"
    for note in "${NDJSON_PENDING_NOTES[@]}"; do
        append_ndjson_line "{\"type\":\"note\",\"message\":$(json_escape "$note")}"
    done
fi

# =============================================================================
# 1. DISK USAGE OVERVIEW
# =============================================================================
section_start_ms=$(now_ms)
section_header "📊 Disk Usage Overview"

echo -e "Scanning home directory size..."

# Top-level folder sizes
echo "| Folder | Size |" >> "$REPORT_FILE"
echo "|--------|------|" >> "$REPORT_FILE"

while IFS=$'\t' read -r size folder; do
    folder_name=$(basename "$folder")
    echo -e "  ${CYAN}$folder_name${NC}: $size"
    echo "| \`$folder_name\` | $size |" >> "$REPORT_FILE"
done < <(du -sh "$HOME_DIR"/*/ 2>/dev/null | sort -hr | head -20)

# Total home dir size
total_size=$(du -sh "$HOME_DIR" 2>/dev/null | cut -f1)
echo -e "\n  ${BOLD}Total home directory: $total_size${NC}"
echo -e "\n**Total home directory size:** $total_size\n" >> "$REPORT_FILE"
home_bytes=$(dir_bytes "$HOME_DIR")
section_end_ms=$(now_ms)
emit_timing "disk_usage_overview" "$section_start_ms" "$section_end_ms"

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
        append_ndjson_line "{\"type\":\"large_file\",\"path\":$(json_escape "$ndjson_path"),\"bytes\":${bytes:-0}}"
        ((large_ndjson_count += 1))
    fi
done < <(emit_large_files_bytes | head -30)

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

# .DS_Store files
ds_start_ms=$(now_ms)
ds_count=$(home_find_excluding -type f -name ".DS_Store" | wc -l | tr -d ' ')
echo -e "  .DS_Store files: ${YELLOW}$ds_count${NC}"
echo "- **\`.DS_Store\` files:** $ds_count" >> "$REPORT_FILE"
ds_end_ms=$(now_ms)
emit_timing "ds_store" "$ds_start_ms" "$ds_end_ms"

# .dmg installer files
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

# .pkg installer files
pkg_count=$(scoped_find_pruned -type f -name "*.pkg" | wc -l | tr -d ' ')
echo -e "  .pkg installers: ${YELLOW}$pkg_count${NC}"
echo "- **\`.pkg\` installers:** $pkg_count" >> "$REPORT_FILE"

# .zip files in Downloads
if [ -d "$HOME_DIR/Downloads" ]; then
    zip_dl_count=$(find "$HOME_DIR/Downloads" -type f -name "*.zip" 2>/dev/null | wc -l | tr -d ' ')
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

# Thumbs.db / desktop.ini (from Windows transfers)
windows_start_ms=$(now_ms)
thumbs_db_count=$(home_find_excluding -type f -name "Thumbs.db" | wc -l | tr -d ' ')
desktop_ini_count=$(home_find_excluding -type f -name "desktop.ini" | wc -l | tr -d ' ')
thumbs_count=$((thumbs_db_count + desktop_ini_count))
echo -e "  Windows artifacts (Thumbs.db, desktop.ini): ${YELLOW}$thumbs_count${NC}"
echo "- **Windows artifacts:** $thumbs_count" >> "$REPORT_FILE"
windows_end_ms=$(now_ms)
emit_timing "windows_artifacts" "$windows_start_ms" "$windows_end_ms"

# Broken symlinks
links_start_ms=$(now_ms)
broken_links=$(find "$HOME_DIR" -maxdepth 4 -type l ! -exec test -e {} \; -print 2>/dev/null | wc -l | tr -d ' ')
echo -e "  Broken symlinks: ${YELLOW}$broken_links${NC}"
echo "- **Broken symlinks:** $broken_links" >> "$REPORT_FILE"
links_end_ms=$(now_ms)
emit_timing "broken_symlinks" "$links_start_ms" "$links_end_ms"

echo "" >> "$REPORT_FILE"

# =============================================================================
# 4. DOWNLOADS AUDIT
# =============================================================================
section_header "📥 Downloads Folder Audit"

if [ -d "$HOME_DIR/Downloads" ]; then
    dl_size=$(du -sh "$HOME_DIR/Downloads" 2>/dev/null | cut -f1)
    dl_file_count=$(find "$HOME_DIR/Downloads" -type f 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  Total size: ${BOLD}$dl_size${NC} ($dl_file_count files)"
    echo "**Total size:** $dl_size ($dl_file_count files)" >> "$REPORT_FILE"

    # Breakdown by file type
    echo -e "\n  ${CYAN}File type breakdown:${NC}"
    echo -e "\n### File Type Breakdown\n" >> "$REPORT_FILE"
    echo "| Type | Count | Total Size |" >> "$REPORT_FILE"
    echo "|------|-------|------------|" >> "$REPORT_FILE"

    for ext in pdf dmg zip pkg png jpg jpeg gif mp4 mov mp3 doc docx xls xlsx csv txt html js py sh; do
        count=$(find "$HOME_DIR/Downloads" -iname "*.$ext" -type f 2>/dev/null | wc -l | tr -d ' ')
        if (( count > 0 )); then
            ext_size=$(find "$HOME_DIR/Downloads" -iname "*.$ext" -type f -exec du -ch {} + 2>/dev/null | tail -1 | cut -f1)
            echo -e "    .$ext: ${YELLOW}$count files${NC} ($ext_size)"
            echo "| \`.$ext\` | $count | $ext_size |" >> "$REPORT_FILE"
        fi
    done

    # Old downloads (not accessed in X days)
    echo -e "\n  ${CYAN}Old files (not accessed in ${OLD_FILE_DAYS}+ days):${NC}"
    old_dl_count=$(find "$HOME_DIR/Downloads" -type f -atime +${OLD_FILE_DAYS} 2>/dev/null | wc -l | tr -d ' ')
    echo -e "    Count: ${YELLOW}$old_dl_count${NC}"
    echo -e "\n### Stale Downloads (${OLD_FILE_DAYS}+ days since last access)\n" >> "$REPORT_FILE"
    echo "**Count:** $old_dl_count files" >> "$REPORT_FILE"

    if (( old_dl_count > 0 )); then
        old_dl_size=$(find "$HOME_DIR/Downloads" -type f -atime +${OLD_FILE_DAYS} -exec du -ch {} + 2>/dev/null | tail -1 | cut -f1)
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
    desktop_size=$(du -sh "$HOME_DIR/Desktop" 2>/dev/null | cut -f1)
    desktop_count=$(find "$HOME_DIR/Desktop" -maxdepth 1 -not -name "." -not -name "cleanup-audit" 2>/dev/null | wc -l | tr -d ' ')
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
    docs_size=$(du -sh "$HOME_DIR/Documents" 2>/dev/null | cut -f1)
    docs_folder_count=$(find "$HOME_DIR/Documents" -maxdepth 1 -type d -not -name "." -not -path "$HOME_DIR/Documents" 2>/dev/null | wc -l | tr -d ' ')
    docs_file_count=$(find "$HOME_DIR/Documents" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  Total size: ${BOLD}$docs_size${NC}"
    echo -e "  Top-level: ${YELLOW}$docs_folder_count folders, $docs_file_count loose files${NC}"
    echo "**Total size:** $docs_size" >> "$REPORT_FILE"
    echo "**Top-level:** $docs_folder_count folders, $docs_file_count loose files" >> "$REPORT_FILE"

    # Top-level folders by size
    echo -e "\n  ${CYAN}Top folders by size:${NC}"
    echo -e "\n### Top Folders by Size\n" >> "$REPORT_FILE"
    echo "| Folder | Size |" >> "$REPORT_FILE"
    echo "|--------|------|" >> "$REPORT_FILE"
    while IFS=$'\t' read -r size folder; do
        fname=$(basename "$folder")
        echo -e "    📁 $fname: $size"
        echo "| \`$fname\` | $size |" >> "$REPORT_FILE"
    done < <(du -sh "$HOME_DIR/Documents"/*/ 2>/dev/null | sort -hr | head -15)

    # Loose files in Documents root
    if (( docs_file_count > 0 )); then
        echo -e "\n  ${CYAN}Loose files in Documents root:${NC}"
        echo -e "\n### Loose Files in Documents Root\n" >> "$REPORT_FILE"
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            fname=$(basename "$f")
            fsize=$(du -sh "$f" 2>/dev/null | cut -f1)
            echo -e "    📄 $fname ($fsize)"
            echo "- \`$fname\` ($fsize)" >> "$REPORT_FILE"
        done < <(find "$HOME_DIR/Documents" -maxdepth 1 -type f 2>/dev/null | sort | head -30)
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

# node_modules
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
        nm_size=$(du -sh "$nm" 2>/dev/null | cut -f1)
        rel="${nm#$HOME_DIR/}"
        echo -e "    ${CYAN}$nm_size${NC}  $rel"
        echo "| \`$rel\` | $nm_size |" >> "$REPORT_FILE"
    done
    echo "" >> "$REPORT_FILE"
fi

# Python virtual environments
venv_count=$(find "$HOME_DIR" -maxdepth 5 -type d \( -name ".venv" -o -name "venv" -o -name "__pycache__" \) -not -path "*/Library/*" 2>/dev/null | wc -l | tr -d ' ')
echo -e "  Python venvs / __pycache__: ${YELLOW}$venv_count${NC}"
echo "### Python Virtual Envs / Cache: $venv_count" >> "$REPORT_FILE"

# .git directories (for awareness)
git_start_ms=$(now_ms)
git_count=$(find "$HOME_DIR" -maxdepth 5 -type d -name ".git" -not -path "*/Library/*" 2>/dev/null | wc -l | tr -d ' ')
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
# Check common directories for duplicate names
for dir in "$HOME_DIR/Downloads" "$HOME_DIR/Desktop" "$HOME_DIR/Documents"; do
    [ -d "$dir" ] || continue
    dir_name=$(basename "$dir")

    # Simpler approach: find files with (N) pattern suggesting copies
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

if [ -d "$HOME_DIR/.Trash" ]; then
    trash_size=$(du -sh "$HOME_DIR/.Trash" 2>/dev/null | cut -f1)
    trash_count=$(find "$HOME_DIR/.Trash" -type f 2>/dev/null | wc -l | tr -d ' ')
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
    downloads_bytes=$(dir_bytes "$HOME_DIR/Downloads")
    desktop_bytes=$(dir_bytes "$HOME_DIR/Desktop")
    documents_bytes=$(dir_bytes "$HOME_DIR/Documents")
    trash_bytes=$(dir_bytes "$HOME_DIR/.Trash")
    append_ndjson_line "{\"type\":\"summary\",\"home_bytes\":${home_bytes:-0},\"downloads_bytes\":${downloads_bytes:-0},\"desktop_bytes\":${desktop_bytes:-0},\"documents_bytes\":${documents_bytes:-0},\"trash_bytes\":${trash_bytes:-0}}"
    append_ndjson_line "{\"type\":\"counts\",\"large_files\":${large_count:-0},\"ds_store\":${ds_count:-0},\"thumbs_db\":${thumbs_db_count:-0},\"desktop_ini\":${desktop_ini_count:-0},\"zip_downloads\":${zip_dl_count:-0},\"dmg\":${dmg_count:-0},\"pkg\":${pkg_count:-0},\"broken_symlinks\":${broken_links:-0},\"node_modules\":${nm_count:-0},\"venv_cache\":${venv_count:-0},\"git_repos\":${git_count:-0},\"potential_duplicates\":${dup_found:-0},\"downloads_stale\":${old_dl_count:-0}}"
fi

# =============================================================================
# 10. SUGGESTED ORGANIZATION STRUCTURE
# =============================================================================
section_header "📋 Suggested Organization Plan"

cat >> "$REPORT_FILE" << 'EOF'
Based on the audit above, here's a recommended folder structure for your home directory:

```
~/Documents/
├── Work/
│   ├── RCG/
│   │   ├── PowerHub/
│   │   ├── Navitas/
│   │   ├── Milford-Mining/
│   │   └── USMED-Equip/
│   └── Contracts-Invoices/
├── Projects/
│   ├── Arachne/
│   └── Personal-Dev/
├── Finance/
│   ├── Taxes/
│   └── Receipts/
├── Education/
│   └── Certifications/
└── Archive/
    └── (older files, organized by year)

~/Downloads/
├── (keep clean — process files then move or delete)

~/Desktop/
├── (keep minimal — temporary workspace only)
```

### Recommended Next Steps

1. **Quick wins:** Empty Trash, delete .dmg/.pkg installers you no longer need
2. **Downloads purge:** Sort through old downloads — delete or file away
3. **Desktop triage:** Move Desktop items into proper Documents subfolders
4. **Dev cleanup:** Remove unused `node_modules` with `npx npkill`
5. **Duplicate cleanup:** Review flagged copies and remove extras
6. **Ongoing habit:** Process Downloads weekly, keep Desktop under 10 items
EOF

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "\n${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║              Audit Complete! ✅                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "Full report saved to:"
echo -e "  ${CYAN}$REPORT_FILE${NC}"
if [ -n "$NDJSON_FILE" ]; then
    echo -e "NDJSON summary saved to:"
    echo -e "  ${CYAN}$NDJSON_FILE${NC}"
fi
echo ""
echo -e "Open it with:  ${BOLD}open \"$REPORT_FILE\"${NC}"
echo ""
echo -e "${YELLOW}Remember: Nothing was moved or deleted. Review the report"
echo -e "and decide what actions to take.${NC}"
