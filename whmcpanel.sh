#!/bin/bash
# =============================================================================
# WHM/cPanel Management Script
# Version: 9.0
#
# Copyright (C) 2026 Sigit Afandhi - HDTEAM-LAB
# Author : Sigit Afandhi HDTEAM-LAB
# Email  : sigit.hdteam@gmail.com
# Date   : November 2026
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# =============================================================================

if [ -z "$BASH_VERSION" ] || (shopt -q posix 2>/dev/null); then
    echo "Script ini membutuhkan Bash. Menjalankan ulang dengan bash..."
    exec bash "$0" "$@"
    exit 1
fi

# =============================================================================
# KONFIGURASI
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'

USER_LIST="/root/user.txt"
FINGERPRINT_DB="/root/shelldetect.db"
FINGERPRINT_URL="https://raw.githubusercontent.com/emposha/PHP-Shell-Detector/master/shelldetect.db"
FINGERPRINT_DIR="/root/fingerprints"
SANESECURITY_FILE="$FINGERPRINT_DIR/sanesecurity.hdb"
SSLBL_JA3_URL="https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
SSLBL_JA3_FILE="$FINGERPRINT_DIR/sslbl_ja3.csv"
SECLISTS_WEBSHELLS_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web_Content/Common-PHP-Filenames.txt"
SECLISTS_WEBSHELLS_FILE="$FINGERPRINT_DIR/seclists_webshells.txt"
WEBSHELL_COLLECTIONS_URL="https://raw.githubusercontent.com/fr4nk404/Webshell-Collections/master/webshell.yar"
WEBSHELL_COLLECTIONS_FILE="$FINGERPRINT_DIR/webshell_collections.yar"

PHP_FPM_YAML="/var/cpanel/ApachePHPFPM/system_pool_defaults.yaml"
PHP_DROPIN_NAME="zz-php2shell-disable-functions.ini"
PHP_DISABLE_DEFAULT="pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,exec,shell_exec,system,passthru,proc_open,popen,proc_close,proc_get_status,proc_nice,proc_terminate,pclose,posix_kill,posix_setuid,posix_setgid,dl,show_source,fsockopen,pfsockopen,stream_socket_client,symlink,link,parse_ini_file"

WS_QUARANTINE_FILE="/root/quarantine_recommended.txt"

declare -A SHELL_HASHES
declare -A KNOWN_SERVICES
SECLISTS_PATTERNS=()
WEBSHELL_YARA_STRINGS=()

# =============================================================================
# PRIMITIF v9.0
# =============================================================================

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
pause() { read -r -p "$(echo -e ${CYAN}"Tekan Enter..."${NC})" _; }
sec_header() { echo -e "${BLUE}========== $1 ==========${NC}"; }
m() { echo -e "${GREEN}$1.${NC} $2"; }

confirm_yn() {
    local a
    if [[ "${2:-N}" == "Y" ]]; then
        read -r -p "$(echo -e ${CYAN}"$1 (Y/n): "${NC})" a
        [[ -z "$a" || "$a" =~ ^[Yy]$ ]]
    else
        read -r -p "$(echo -e ${CYAN}"$1 (y/N): "${NC})" a
        [[ "$a" =~ ^[Yy]$ ]]
    fi
}

need_file() { [[ -f "$1" ]] || { print_error "File $1 tidak ada."; return 1; }; }

pick_user() {
    local __out="$1" __p="${2:-Pilih: }" __u=() __i __in __ix
    need_file "$USER_LIST" || return 1
    mapfile -t __u < "$USER_LIST"
    [[ ${#__u[@]} -gt 0 ]] || { print_error "Daftar user kosong."; return 1; }
    for __i in "${!__u[@]}"; do printf "%3d. %s\n" $((__i+1)) "${__u[$__i]}"; done
    read -r -p "$(echo -e ${CYAN}"$__p"${NC})" __in
    if [[ "$__in" =~ ^[0-9]+$ ]]; then
        __ix=$((__in-1))
        (( __ix >= 0 && __ix < ${#__u[@]} )) || { print_error "Nomor tidak valid."; return 1; }
        __in="${__u[$__ix]}"
    fi
    [[ -n "$__in" ]] || { print_error "Kosong."; return 1; }
    printf -v "$__out" '%s' "$__in"
}

detect_cores() {
    local n
    n=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
    (( n > 8 )) && n=8
    (( n < 1 )) && n=1
    echo "$n"
}

WS_PARALLEL_JOBS=$(detect_cores)

human_size() {
    awk -v b="$1" 'BEGIN {
        if (b < 1048576) printf "%.2f KB", b/1024
        else if (b < 1073741824) printf "%.2f MB", b/1048576
        else printf "%.2f GB", b/1073741824
    }'
}

validate_ip_cidr() {
    local input="$1"
    if [[ "$input" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        local ip_part="${input%%/*}" prefix="${input##*/}"
        IFS='.' read -r a b c d <<< "$ip_part"
        if (( a >= 0 && a <= 255 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 0 && d <= 255 )); then
            if [[ "$input" == *"/"* ]]; then
                (( prefix >= 0 && prefix <= 32 )) && return 0
                print_error "Prefix CIDR harus 0–32."; return 1
            fi
            return 0
        fi
    fi
    print_error "Format IP/CIDR tidak valid."
    return 1
}

install_package() {
    local pkg=$1
    command -v dnf &>/dev/null && { dnf install -y "$pkg"; return; }
    command -v yum &>/dev/null && { yum install -y "$pkg"; return; }
    print_error "Package manager tidak ditemukan."
    return 1
}

progress_bar() {
    local current=$1 total=$2
    [[ $total -le 0 ]] && total=1
    [[ $current -gt $total ]] && current=$total
    [[ $current -lt 0 ]] && current=0
    local w=50 p=$(( current * 100 / total )) f=$(( p * w / 100 )) e=$(( w - f ))
    printf "\r${CYAN}[${NC}"
    printf "%${f}s" | tr ' ' '#'
    printf "%${e}s" | tr ' ' '.'
    printf "${CYAN}]${NC} ${GREEN}%3d%%${NC} (${current}/${total})" "$p"
}

# =============================================================================
# FINGERPRINT
# =============================================================================

load_fingerprint_db() {
    if [[ ! -f "$FINGERPRINT_DB" ]] && command -v wget &>/dev/null; then
        print_info "Download fingerprint DB (shelldetect.db)..."
        if wget -q -O "$FINGERPRINT_DB" "$FINGERPRINT_URL" 2>/dev/null && [[ -s "$FINGERPRINT_DB" ]]; then
            print_ok "Downloaded."
        else
            print_warn "Gagal download fingerprint DB."
            rm -f "$FINGERPRINT_DB" 2>/dev/null
        fi
    fi
    if [[ -f "$FINGERPRINT_DB" ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[a-f0-9]{32}:[^:]+$ ]] && SHELL_HASHES["${line%%:*}"]="${line#*:}"
        done < <(base64 -d "$FINGERPRINT_DB" 2>/dev/null | strings | grep -E '^[a-f0-9]{32}:[^:]+$' || true)
    fi
}

load_sanesecurity() {
    print_info "Loading Sanesecurity..."
    [[ -f "$SANESECURITY_FILE" ]] || { print_warn "File tidak ada, skip."; return 1; }
    while IFS= read -r line; do
        if [[ "$line" =~ ^[a-f0-9]{32}:[0-9]+: ]]; then
            SHELL_HASHES["$(echo "$line" | cut -d: -f1)"]="Sanesecurity:$(echo "$line" | cut -d: -f3-)"
        fi
    done < <(grep -E '^[a-f0-9]{32}:' "$SANESECURITY_FILE" 2>/dev/null || true)
}

query_teamcymru_mhr() {
    local r=$(dig +short "$1.malware.hash.cymru.com" TXT 2>/dev/null)
    [[ "$r" == *"127.0.0.2"* ]] && echo "TeamCymru:MHR"
}

query_abusech_bazaar() {
    local r=$(curl -s -m 5 -X POST "https://bazaar.abuse.ch/api/v1/" -H "Auth-Key: " -d "query=get_info&hash=$1" 2>/dev/null)
    echo "$r" | grep -q '"query_status":"ok"' && echo "AbuseCh:Bazaar"
}

load_sslbl_ja3() {
    if [[ ! -f "$SSLBL_JA3_FILE" ]]; then
        print_info "Download JA3 fingerprints (≈5 MB, 10-30 dtk)..."
        wget -q -O "$SSLBL_JA3_FILE" "$SSLBL_JA3_URL" 2>/dev/null || { print_warn "Gagal download SSLBL JA3."; return 1; }
    fi
    while IFS=, read -r md5 _ _ reason; do
        [[ "$md5" == "ja3_md5" ]] && continue
        SHELL_HASHES["$md5"]="SSLBL:JA3 ($reason)"
    done < <(tail -n +2 "$SSLBL_JA3_FILE" 2>/dev/null || true)
}

load_seclists() {
    print_info "Loading SecLists..."
    if [[ ! -f "$SECLISTS_WEBSHELLS_FILE" ]]; then
        if ! wget -q -O "$SECLISTS_WEBSHELLS_FILE" "$SECLISTS_WEBSHELLS_URL" 2>/dev/null; then
            print_warn "Gagal download SecLists, pakai fallback."
            SECLISTS_PATTERNS=(shell.php cmd.php backdoor.php webshell.php eval.php system.php exec.php c99.php r57.php wso.php)
            return 0
        fi
    fi
    SECLISTS_PATTERNS=()
    while IFS= read -r p; do
        [[ -z "$p" || "$p" =~ ^# ]] && continue
        SECLISTS_PATTERNS+=("$p")
    done < "$SECLISTS_WEBSHELLS_FILE"
    print_info "Loaded ${#SECLISTS_PATTERNS[@]} patterns."
}

load_webshell_collections() {
    print_info "Loading YARA patterns..."
    if [[ ! -f "$WEBSHELL_COLLECTIONS_FILE" ]]; then
        if ! wget -q -O "$WEBSHELL_COLLECTIONS_FILE" "$WEBSHELL_COLLECTIONS_URL" 2>/dev/null; then
            print_warn "Gagal download YARA, pakai fallback."
            WEBSHELL_YARA_STRINGS=(base64_decode gzinflate eval system exec shell_exec passthru popen proc_open)
            return 0
        fi
    fi
    WEBSHELL_YARA_STRINGS=()
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*\$[a-zA-Z0-9_]+[[:space:]]*=[[:space:]]*\"(.*)\" ]] && WEBSHELL_YARA_STRINGS+=("${BASH_REMATCH[1]}")
    done < <(grep -E '^\s*\$[a-zA-Z0-9_]+\s*=\s*".*"' "$WEBSHELL_COLLECTIONS_FILE" 2>/dev/null || true)
    print_info "Loaded ${#WEBSHELL_YARA_STRINGS[@]} YARA patterns."
}

load_all_fingerprints() {
    load_fingerprint_db
    load_sanesecurity
    load_sslbl_ja3
    load_seclists
    load_webshell_collections
}

init_known_services() {
    local services=(httpd nginx apache2 php-fpm mysql mariadb mysqld exim dovecot named sshd crond
                    systemd rsyslog firewalld csf lfd cphulkd tailwatchd cpanellogd cpdavd spamd clamd
                    freshclam ntpd chronyd docker redis memcached elasticsearch logstash kibana pure-ftpd
                    proftpd vsftpd sendmail postfix syslog-ng systemd-journald systemd-timesyncd
                    systemd-resolved saslauthd cpwrapd cpsrvd)
    for svc in "${services[@]}"; do KNOWN_SERVICES["$svc"]=1; done
}

# =============================================================================
# USER LIST
# =============================================================================

get_user_list() {
    if command -v whmapi1 &>/dev/null; then
        local u=$(whmapi1 listusers 2>/dev/null | grep -E "^user:" | awk '{print $2}')
        [[ -n "$u" ]] && echo "$u" && return 0
    fi
    if [[ -d "/var/cpanel/users/" ]]; then
        local u=$(ls /var/cpanel/users/ 2>/dev/null | grep -v -E '^(\.|cpanel|root)$')
        [[ -n "$u" ]] && echo "$u" && return 0
    fi
    [[ -d "/home" ]] || return 1
    local user
    for dir in /home/*/; do
        user=$(basename "$dir")
        [[ "$user" =~ ^(virtfs|cpanel|clamav|cPanelInstall|0_README_BEFORE_DELETING_VIRTFS)$ ]] && continue
        [[ -f "/var/cpanel/users/$user" ]] && echo "$user"
    done
    return 0
}

sync_user_list() {
    local temp=$(mktemp)
    if get_user_list > "$temp"; then
        local c=$(wc -l < "$temp")
        if [[ $c -eq 0 ]]; then
            print_error "Tidak ada user ditemukan."
            rm -f "$temp"; return 1
        fi
    else
        print_error "Gagal mendapatkan daftar user."
        rm -f "$temp"; return 1
    fi
    if [[ ! -f "$USER_LIST" ]]; then
        mv "$temp" "$USER_LIST"
        print_info "Berhasil, total $(wc -l < "$USER_LIST") user tercatat."
        return 0
    fi
    if cmp -s "$temp" "$USER_LIST"; then
        print_info "File $USER_LIST sudah sesuai."
        rm -f "$temp"; return 0
    fi
    local old=$(wc -l < "$USER_LIST")
    print_warn "Daftar user berubah ($old → $c)."
    if confirm_yn "Update $USER_LIST?" Y; then
        mv "$temp" "$USER_LIST"
        print_info "File diperbarui. Total $(wc -l < "$USER_LIST") user."
    else
        print_info "Tetap menggunakan yang lama."
        rm -f "$temp"
    fi
}

# =============================================================================
# MENU A: 1-5 USER & AKUN
# =============================================================================

generate_user_txt() {
    print_info "Generate ulang $USER_LIST..."
    if get_user_list > "$USER_LIST"; then
        local c=$(wc -l < "$USER_LIST")
        [[ $c -gt 0 ]] && print_info "Berhasil, $c user." || print_error "Tidak ada user."
    else
        print_error "Gagal."
    fi
    pause
}

update_user_txt() {
    clear
    sec_header "UPDATE USER CPANEL"
    print_info "Sinkronisasi ke $USER_LIST ..."
    sync_user_list
    pause
}

manage_accounts() {
    local action action_cmd target input idx username
    local -a users=()
    clear
    sec_header "MANAJEMEN AKUN"
    echo "Pilih tindakan:"
    m 1 "Suspend akun"
    m 2 "Unsuspend akun"
    m 3 "Terminate akun (HAPUS PERMANEN)"
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih [0-3]: "${NC})" action
    case $action in
        1) action_cmd="suspend" ;;
        2) action_cmd="unsuspend" ;;
        3) action_cmd="terminate" ;;
        0) return ;;
        *) print_error "Pilihan salah"; pause; return ;;
    esac
    echo ""
    echo "Target:"
    m 1 "Satu user"
    m 2 "Semua user (user.txt)"
    read -r -p "$(echo -e ${CYAN}"Pilih [1-2]: "${NC})" target
    if [[ "$target" == "1" ]]; then
        pick_user username "Nomor atau username: " || { pause; return; }
        users=("$username")
    elif [[ "$target" == "2" ]]; then
        need_file "$USER_LIST" || { pause; return; }
        mapfile -t users < "$USER_LIST"
    else
        print_error "Pilihan salah"; pause; return
    fi
    echo ""
    echo "Tindakan: $action_cmd | Jumlah: ${#users[@]}"
    [[ ${#users[@]} -le 10 ]] && printf '  %s\n' "${users[@]}" || { printf '  %s\n' "${users[@]:0:10}"; echo "  ..."; }
    [[ "$action_cmd" == "terminate" ]] && echo -e "${RED}PERINGATAN: Terminate hapus PERMANEN!${NC}"
    confirm_yn "Lanjutkan?" || { print_info "Dibatalkan."; pause; return; }
    local user
    for user in "${users[@]}"; do
        id "$user" &>/dev/null || { print_warn "User $user tidak ada, skip."; continue; }
        case $action_cmd in
            suspend) print_info "Suspend $user"; /scripts/suspendacct "$user" 2>/dev/null ;;
            unsuspend) print_info "Unsuspend $user"; /scripts/unsuspendacct "$user" 2>/dev/null ;;
            terminate) print_info "Terminate $user"; /scripts/terminateacct "$user" 2>/dev/null ;;
        esac
    done
    print_info "Selesai."
    pause
}

backup_restore_user() {
    local br user filepath
    clear
    sec_header "BACKUP / RESTORE USER"
    m 1 "Backup user"
    m 2 "Restore user"
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih [0-2]: "${NC})" br
    case $br in
        1)
            read -r -p "$(echo -e ${CYAN}"Username: "${NC})" user
            [[ -z $user ]] && { echo "Kosong"; pause; return; }
            mkdir -p /home/backup
            print_info "Backup $user..."
            /scripts/pkgacct "$user" /home/backup
            print_info "Selesai di /home/backup/"
            ;;
        2)
            read -r -p "$(echo -e ${CYAN}"Username: "${NC})" user
            read -r -p "$(echo -e ${CYAN}"Path backup: "${NC})" filepath
            [[ -z $filepath ]] && { echo "Kosong"; pause; return; }
            [[ ! -f "$filepath" ]] && print_error "File tidak ada." && pause && return
            print_info "Restore $user dari $filepath..."
            /scripts/restorepkg "$filepath"
            print_info "Selesai."
            ;;
        0) return ;;
        *) echo "Pilihan salah" ;;
    esac
    pause
}

run_autossl() {
    local target username confirm
    clear
    sec_header "RUN AUTOSSL"
    m 1 "Satu user"
    m 2 "Semua user"
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih [0-2]: "${NC})" target
    case "$target" in
        0) return ;;
        2)
            echo ""
            echo "AutoSSL untuk SEMUA user"
            echo -e "${YELLOW}CATATAN: bisa kena rate-limit Let's Encrypt.${NC}"
            confirm_yn "Lanjutkan?" || { print_info "Dibatalkan."; pause; return; }
            print_info "Trigger via whmapi1..."
            whmapi1 start_autossl_for_all_users &>/dev/null && print_ok "Berhasil." || print_error "Gagal."
            pause; return
            ;;
        1)
            pick_user username "Nomor atau username: " || { pause; return; }
            id "$username" &>/dev/null || { print_error "User tidak ditemukan."; pause; return; }
            echo ""
            echo "AutoSSL untuk $username"
            confirm_yn "Lanjutkan?" || { print_info "Dibatalkan."; pause; return; }
            print_info "Menjalankan AutoSSL untuk $username..."
            if whmapi1 start_autossl_for_user user="$username" &>/dev/null; then
                print_ok "Via whmapi1"
            elif /scripts/autossl_check --user="$username" &>/dev/null; then
                print_ok "Via /scripts/autossl_check"
            else
                print_error "Gagal."
            fi
            pause; return
            ;;
        *) print_error "Pilihan salah"; pause; return ;;
    esac
}

# =============================================================================
# MENU B: 6 DISABLE PHP FUNCTIONS
# =============================================================================

get_existing_disable_functions() {
    local existing="" php_d f
    for php_d in /opt/cpanel/ea-php*/root/etc/php.d; do
        [[ -d "$php_d" ]] || continue
        f="$php_d/$PHP_DROPIN_NAME"
        [[ -f "$f" ]] && { existing=$(grep -E '^[[:space:]]*disable_functions' "$f" 2>/dev/null | head -1 | sed 's/.*=//' | xargs); [[ -n "$existing" ]] && break; }
    done
    if [[ -z "$existing" ]] && [[ -f "$PHP_FPM_YAML" ]]; then
        existing=$(grep 'php_admin_value\[disable_functions\]' "$PHP_FPM_YAML" 2>/dev/null | head -1 | sed "s/.*value: *'//; s/'.*//")
    fi
    echo "$existing"
}

get_php2shell_status() {
    local status="On" php_d f g
    for php_d in /opt/cpanel/ea-php*/root/etc/php.d; do
        [[ -d "$php_d" ]] || continue
        for f in "$php_d/zz-php2shell-mitigation.ini" "$php_d/$PHP_DROPIN_NAME"; do
            if [[ -f "$f" ]] && grep -qE '^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=[[:space:]]*Off' "$f" 2>/dev/null; then
                status="Off"; break 2
            fi
        done
    done
    if [[ "$status" == "On" ]] && [[ -f "$PHP_FPM_YAML" ]] && grep -qE "php_admin_flag\[session\.upload_progress\.enabled\].*value: *'off'" "$PHP_FPM_YAML" 2>/dev/null; then
        status="Off"
    fi
    echo "$status"
}

detect_php_targets() {
    local targets=() php_d
    for php_d in /opt/cpanel/ea-php*/root/etc/php.d; do
        [[ -d "$php_d" ]] && targets+=("$php_d")
    done
    [[ ${#targets[@]} -gt 0 ]] && printf '%s\n' "${targets[@]}"
}

apply_disable_functions() {
    local disable_list="$1" apply_p2s="$2" dry_run="$3"
    local suffix=".bak-disablefn-$(date +%Y%m%d-%H%M%S)"
    local changed=() new_files=() updated_files=() php_d target content sl fpm_line p2s_line needs_update build_ok=true

    for php_d in /opt/cpanel/ea-php*/root/etc/php.d; do
        [[ -d "$php_d" ]] || continue
        target="$php_d/$PHP_DROPIN_NAME"
        content="disable_functions = $disable_list"
        if [[ "$apply_p2s" == "true" ]]; then
            content+=$'\n'"session.upload_progress.enabled = Off"
        elif [[ -f "$target" ]] && grep -qE '^[[:space:]]*session\.upload_progress\.enabled' "$target" 2>/dev/null; then
            sl=$(grep -E '^[[:space:]]*session\.upload_progress\.enabled' "$target" | head -1)
            content+=$'\n'"$sl"
        fi
        if [[ -f "$target" ]] && [[ "$(cat "$target" 2>/dev/null)" == "$content" ]]; then
            echo "  [SKIP] $target"; continue
        fi
        if [[ "$dry_run" == "true" ]]; then
            [[ -f "$target" ]] && echo "  [DRY] Update: $target" || echo "  [DRY] Baru  : $target"
        else
            [[ -f "$target" ]] && { cp -a "$target" "${target}${suffix}"; updated_files+=("$target"); } || new_files+=("$target")
            echo "$content" > "$target"
            echo "  [OK] $target"
            changed+=("$target")
        fi
    done

    if [[ -f "$PHP_FPM_YAML" ]]; then
        fpm_line="php_admin_value_disable_functions: { name: 'php_admin_value[disable_functions]', value: '$disable_list' }"
        p2s_line="php_admin_flag_session_upload_progress_enabled: { name: 'php_admin_flag[session.upload_progress.enabled]', value: 'off' }"
        needs_update=false
        ! grep -qF "$fpm_line" "$PHP_FPM_YAML" 2>/dev/null && needs_update=true
        if [[ "$apply_p2s" == "true" ]] && ! grep -qE "php_admin_flag\[session\.upload_progress\.enabled\].*value: *'off'" "$PHP_FPM_YAML" 2>/dev/null; then
            needs_update=true
        fi
        if [[ "$needs_update" == "false" ]]; then
            echo "  [SKIP] $PHP_FPM_YAML"
        elif [[ "$dry_run" == "true" ]]; then
            echo "  [DRY] Update: $PHP_FPM_YAML"
        else
            cp -a "$PHP_FPM_YAML" "${PHP_FPM_YAML}${suffix}"
            updated_files+=("$PHP_FPM_YAML")
            sed -i '/php_admin_value\[disable_functions\]/d' "$PHP_FPM_YAML"
            echo "$fpm_line" >> "$PHP_FPM_YAML"
            if [[ "$apply_p2s" == "true" ]]; then
                sed -i '/php_admin_flag\[session\.upload_progress\.enabled\]/d' "$PHP_FPM_YAML"
                echo "$p2s_line" >> "$PHP_FPM_YAML"
            fi
            echo "  [OK] $PHP_FPM_YAML"
            changed+=("$PHP_FPM_YAML")
        fi
    else
        print_warn "File tidak ditemukan: $PHP_FPM_YAML"
    fi

    if [[ "$dry_run" == "true" ]]; then
        echo ""
        echo "  [DRY] php_fpm_config --rebuild"
        echo "  [DRY] restartsrv_apache_php_fpm"
        echo "  [DRY] restartsrv_httpd"
    elif [[ ${#changed[@]} -gt 0 ]]; then
        echo ""
        echo "  [3/3] Rebuild & restart..."
        /usr/local/cpanel/scripts/php_fpm_config --rebuild >/dev/null 2>&1 && echo "    php_fpm_config ................. OK" || { echo "    php_fpm_config ................. GAGAL"; build_ok=false; }
        /usr/local/cpanel/scripts/restartsrv_apache_php_fpm >/dev/null 2>&1 && echo "    restartsrv_apache_php_fpm ...... OK" || { echo "    restartsrv_apache_php_fpm ...... GAGAL"; build_ok=false; }
        /usr/local/cpanel/scripts/restartsrv_httpd >/dev/null 2>&1 && echo "    restartsrv_httpd ............... OK" || { echo "    restartsrv_httpd ............... GAGAL"; build_ok=false; }
    fi

    export APPLY_BACKUP_SUFFIX="$suffix"
    export APPLY_NEW_FILES="${new_files[*]}"
    export APPLY_UPDATED_FILES="${updated_files[*]}"
    export APPLY_BUILD_OK="$build_ok"

    echo ""
    if [[ ${#changed[@]} -eq 0 ]]; then
        print_info "Tidak ada file berubah."
    else
        print_info "File diubah: ${#changed[@]}"
        local f; for f in "${changed[@]}"; do echo "  - $f"; done
    fi
}

rollback_disable_functions() {
    local suffix="$1" new_files=($2) updated_files=($3) f
    print_info "Rollback..."
    for f in "${new_files[@]}"; do [[ -f "$f" ]] && rm -f "$f" && echo "  [HAPUS] $f"; done
    for f in "${updated_files[@]}"; do [[ -f "${f}${suffix}" ]] && { mv "${f}${suffix}" "$f"; echo "  [PULIH] $f"; }; done
    echo ""
    print_info "Rebuild & restart..."
    /usr/local/cpanel/scripts/php_fpm_config --rebuild >/dev/null 2>&1 && echo "    php_fpm_config ................. OK" || echo "    php_fpm_config ................. GAGAL"
    /usr/local/cpanel/scripts/restartsrv_apache_php_fpm >/dev/null 2>&1 && echo "    restartsrv_apache_php_fpm ...... OK" || echo "    restartsrv_apache_php_fpm ...... GAGAL"
    /usr/local/cpanel/scripts/restartsrv_httpd >/dev/null 2>&1 && echo "    restartsrv_httpd ............... OK" || echo "    restartsrv_httpd ............... GAGAL"
    print_ok "Rollback selesai."
}

disable_php_functions() {
    local opt new_list apply_p2s current p2s php_versions ini_count has_yaml cnt d t add dry confirm dry_run rb
    local -a php_dirs=()
    while true; do
        clear
        sec_header "DISABLE PHP FUNCTIONS (RCE + PHP2Shell)"
        echo ""
        echo -e "${CYAN}[DETEKSI] Memeriksa konfigurasi PHP...${NC}"
        php_dirs=()
        mapfile -t php_dirs < <(detect_php_targets)
        has_yaml=false
        [[ -f "$PHP_FPM_YAML" ]] && has_yaml=true

        if [[ ${#php_dirs[@]} -eq 0 ]] && [[ "$has_yaml" == "false" ]]; then
            echo ""; print_error "Tidak ditemukan instalasi PHP kompatibel."
            echo "  - Tidak ada /opt/cpanel/ea-php*/root/etc/php.d"
            echo "  - Tidak ada $PHP_FPM_YAML"
            echo ""
            pause; return
        fi

        php_versions=""
        for d in "${php_dirs[@]}"; do
            php_versions+=" $(echo "$d" | sed -E 's|.*ea-php([0-9]+).*|\1|')"
        done
        php_versions=$(echo "$php_versions" | xargs)

        ini_count=0
        for d in "${php_dirs[@]}"; do [[ -f "$d/$PHP_DROPIN_NAME" ]] && ((ini_count++)); done

        current=$(get_existing_disable_functions)
        p2s=$(get_php2shell_status)

        echo "  ea-php        : ${php_versions:-(tidak ada)}  (${#php_dirs[@]} versi)"
        [[ "$ini_count" -gt 0 ]] && echo "  Drop-in .ini  : ADA ($ini_count)" || echo "  Drop-in .ini  : tidak ditemukan"
        [[ "$has_yaml" == "true" ]] && echo "  PHP-FPM YAML  : ADA" || echo "  PHP-FPM YAML  : tidak ditemukan"
        echo ""
        if [[ -n "$current" ]]; then
            echo -e "${CYAN}  disable_functions:${NC}"
            echo "    $current" | fold -w 100 -s | sed 's/^/    /'
        else
            echo -e "${YELLOW}  disable_functions: (kosong)${NC}"
        fi
        echo ""
        [[ "$p2s" == "Off" ]] && echo -e "  session.upload_progress: Off  ${GREEN}✓ dimitigasi${NC}" || echo -e "  session.upload_progress: On   ${YELLOW}⚠ belum${NC}"
        echo ""
        echo "  Status:"
        [[ "$p2s" == "Off" ]] && echo -e "    ${GREEN}✓${NC} PHP2Shell mitigation : SUDAH" || echo -e "    ${RED}✗${NC} PHP2Shell mitigation : BELUM"
        [[ -n "$current" ]] && echo -e "    ${YELLOW}⚠${NC} disable_functions    : ADA" || echo -e "    ${RED}✗${NC} disable_functions    : BELUM"
        echo ""
        echo "Opsi:"
        m 1 "Auto set default + PHP2Shell mitigation"
        m 2 "Tambah fungsi (append)"
        m 0 "Kembali"
        read -r -p "$(echo -e ${CYAN}"Pilih [0-2]: "${NC})" opt

        new_list=""; apply_p2s="false"
        case "$opt" in
            1) new_list="$PHP_DISABLE_DEFAULT"; apply_p2s="true" ;;
            2)
                if [[ -z "$current" ]]; then
                    print_warn "disable_functions kosong."
                    confirm_yn "Inisialisasi dengan input Anda?" || { pause; continue; }
                fi
                echo ""
                read -r -p "$(echo -e ${CYAN}"Fungsi baru (pisah koma): "${NC})" add
                [[ -z "$add" ]] && { print_error "Kosong."; pause; continue; }
                if ! [[ "$add" =~ ^[a-zA-Z0-9_,[:space:]]+$ ]]; then
                    print_error "Format tidak valid."; pause; continue
                fi
                add=$(echo "$add" | tr -d '[:space:]')
                echo ""; echo -e "${CYAN}[CEK]${NC} Format valid"
                if [[ -n "$current" ]]; then
                    new_list=$(echo "${current},${add}" | tr ',' '\n' | awk 'NF && !seen[$0]++' | paste -sd ',' -)
                    local dc uc
                    dc=$(echo "${current},${add}" | tr ',' '\n' | awk 'NF' | wc -l)
                    uc=$(echo "$new_list" | tr ',' '\n' | awk 'NF' | wc -l)
                    [[ $dc -gt $uc ]] && echo "  ⚠ $((dc - uc)) duplikat dibuang" || echo "  ✓ Tidak ada duplikat"
                else
                    new_list="$add"
                fi
                if [[ "$p2s" == "On" ]]; then
                    echo ""
                    confirm_yn "Aktifkan PHP2Shell mitigation?" && apply_p2s="true"
                fi
                ;;
            0) return ;;
            *) print_error "Pilihan salah"; pause; continue ;;
        esac

        echo ""
        echo -e "${CYAN}[PREVIEW]${NC}"
        for d in "${php_dirs[@]}"; do
            t="$d/$PHP_DROPIN_NAME"
            [[ -f "$t" ]] && echo "    [UPDATE] $t" || echo "    [BARU]   $t"
        done
        [[ "$has_yaml" == "true" ]] && echo "    [UPDATE] $PHP_FPM_YAML"
        echo ""
        cnt=$(echo "$new_list" | tr ',' '\n' | wc -l)
        if [[ "$opt" == "1" ]] && [[ -n "$current" ]]; then
            echo -e "  ${YELLOW}[PERINGATAN] Opsi 1 akan MENIMPA list saat ini.${NC}"
            echo "  List lama:"
            echo "    $current" | fold -w 100 -s | sed 's/^/    /'
            echo ""
        fi
        echo "  disable_functions ($cnt):"
        echo "    $new_list" | fold -w 100 -s | sed 's/^/    /'
        echo ""
        [[ "$apply_p2s" == "true" ]] && echo -e "  PHP2Shell: ${GREEN}session.upload_progress.enabled = Off${NC}" || echo -e "  PHP2Shell: ${YELLOW}tidak diubah${NC}"
        echo ""

        confirm_yn "[MODE] Dry-run?" && dry_run="true" || dry_run="false"

        confirm_yn "[CONFIRM] Terapkan?" || { print_info "Dibatalkan."; pause; continue; }

        echo ""
        echo -e "${CYAN}[MULAI] Menerapkan...${NC}"
        echo ""
        apply_disable_functions "$new_list" "$apply_p2s" "$dry_run"

        if [[ "$dry_run" == "true" ]]; then
            echo ""
            echo -e "${YELLOW}[DRY-RUN] Tidak ada perubahan aktual.${NC}"
            pause; continue
        fi

        if [[ "$APPLY_BUILD_OK" != "true" ]]; then
            echo ""
            print_warn "Restart gagal."
            m 1 "Rollback"
            m 2 "Biarkan"
            m 0 "Kembali"
            read -r -p "$(echo -e ${CYAN}"Pilih [0-2]: "${NC})" rb
            case "$rb" in
                1) rollback_disable_functions "$APPLY_BACKUP_SUFFIX" "$APPLY_NEW_FILES" "$APPLY_UPDATED_FILES" ;;
                0|2) ;;
            esac
            pause; return
        fi

        echo ""
        echo -e "${GREEN}[OK] Selesai.${NC}"
        echo ""
        echo "Verifikasi:"
        echo "  <?php var_export(ini_get('disable_functions')); ?>"
        echo ""
        echo -e "${YELLOW}PENTING:${NC}"
        echo "  - eval() tidak bisa di-disable (language construct)"
        echo "  - disable_functions BUKAN pengganti patch PHP2Shell"
        echo "  - Segera update PHP ke 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"
        echo ""
        pause
        continue
    done
}

# =============================================================================
# 7 CSF
# =============================================================================

csf_installed() { command -v csf &>/dev/null || [[ -x /usr/sbin/csf ]] || [[ -x /usr/local/sbin/csf ]] || [[ -f /etc/csf/csf.conf ]]; }

get_csf_bin() {
    command -v csf &>/dev/null && { command -v csf; return; }
    [[ -x /usr/sbin/csf ]] && { echo /usr/sbin/csf; return; }
    [[ -x /usr/local/sbin/csf ]] && { echo /usr/local/sbin/csf; return; }
    echo ""
}

detect_csf() {
    local csf_bin=$(get_csf_bin)
    echo ""
    sec_header "DETEKSI CSF"
    if csf_installed; then
        print_ok "CSF terdeteksi."
        [[ -n "$csf_bin" ]] && echo "Binary : $csf_bin"
        if [[ -f /etc/csf/csf.conf ]]; then
            local testing=$(awk -F= '/^[[:space:]]*TESTING[[:space:]]*=/{gsub(/[ " ]/,"",$2); print $2; exit}' /etc/csf/csf.conf)
            echo "Config : /etc/csf/csf.conf"
            [[ "$testing" == "1" ]] && print_warn "TESTING mode." || print_info "TESTING mode: OFF"
        fi
        [[ -n "$csf_bin" ]] && "$csf_bin" -v 2>/dev/null || true
        return 0
    fi
    print_warn "CSF tidak terinstal."
    confirm_yn "Install CSF?" && install_csf || print_info "Dibatalkan."
}

install_csf() {
    print_info "Instalasi CSF..."
    if command -v yum &>/dev/null; then
        yum install -y cpanel-csf || { print_error "Gagal."; return 1; }
    elif command -v dnf &>/dev/null; then
        dnf install -y cpanel-csf || { print_error "Gagal."; return 1; }
    else print_error "yum/dnf tidak ada."; return 1; fi
    [[ -f /etc/csf/csf.conf ]] && sed -i -E 's/^[[:space:]]*TESTING[[:space:]]*=.*/TESTING = "0"/' /etc/csf/csf.conf
    print_ok "CSF terinstal."
}

uninstall_csf() {
    clear
    sec_header "UNINSTALL CSF"
    if ! csf_installed && ! rpm -q cpanel-csf &>/dev/null; then
        print_warn "CSF tidak ada."; pause; return
    fi
    read -r -p "$(echo -e ${CYAN}"Ketik 'YES' untuk konfirmasi: "${NC})" confirm
    [[ "$confirm" != "YES" ]] && { print_info "Dibatalkan."; pause; return; }
    if command -v yum &>/dev/null; then yum remove -y cpanel-csf
    elif command -v dnf &>/dev/null; then dnf remove -y cpanel-csf
    else print_error "yum/dnf tidak ada."; pause; return; fi
    csf_installed && print_error "Masih terdeteksi." || print_ok "Berhasil uninstall."
    pause
}

csf_mode_menu() {
    clear
    sec_header "MODE CSF FIREWALL"
    if ! csf_installed; then print_error "CSF tidak terinstal."; pause; return; fi
    local csf=$(get_csf_bin) mc
    [[ -z "$csf" ]] && { print_error "Binary CSF tidak ada."; pause; return; }
    m 1 "Enable"
    m 2 "Disable"
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih [0-2]: "${NC})" mc
    case "$mc" in
        1) confirm_yn "Yakin ENABLE?" && { print_info "Mengaktifkan..."; "$csf" -e; } || print_info "Dibatalkan." ;;
        2) confirm_yn "Yakin DISABLE?" && { print_warn "Menonaktifkan..."; "$csf" -x; } || print_info "Dibatalkan." ;;
        0) return ;;
        *) print_error "Pilihan salah." ;;
    esac
    pause
}

csf_quick_action() {
    local flag="$1" label="$2" ip csf
    read -r -p "$(echo -e ${CYAN}"IP yang akan di-${label}: "${NC})" ip
    csf=$(get_csf_bin)
    [[ -z "$ip" ]] && { print_error "IP kosong."; return 1; }
    [[ -z "$csf" ]] && { print_error "CSF binary tidak ada."; return 1; }
    "$csf" "$flag" "$ip"
}

manage_csf() {
    local ch csf confirm
    while true; do
        clear
        sec_header "PENGELOLAAN CSF FIREWALL"
        m 1 "Detect CSF dan Install"
        m 2 "Pilih Mode CSF"
        m 3 "Uninstall CSF"
        m 4 "Quick Allow IP"
        m 5 "Quick Deny IP"
        m 6 "Quick Ignore IP"
        m 7 "Quick Unblock IP"
        m 8 "Firewall Start"
        m 9 "Firewall Stop"
        m 10 "Firewall Restart"
        m 11 "Flush All Block"
        m 0 "Kembali"
        read -r -p "$(echo -e ${CYAN}"Pilih [0-11]: "${NC})" ch
        case "$ch" in
            1) detect_csf; pause ;;
            2) csf_mode_menu ;;
            3) uninstall_csf ;;
            4) csf_quick_action "-a" "allow"; pause ;;
            5) csf_quick_action "-d" "deny"; pause ;;
            6) csf_quick_action "-i" "ignore"; pause ;;
            7) csf_quick_action "-u" "unblock"; pause ;;
            8) csf=$(get_csf_bin); [[ -n "$csf" ]] && "$csf" -s || print_error "CSF tidak terinstal."; pause ;;
            9) csf=$(get_csf_bin); [[ -n "$csf" ]] && "$csf" -q || print_error "CSF tidak terinstal."; pause ;;
            10) csf=$(get_csf_bin); [[ -n "$csf" ]] && "$csf" -r || print_error "CSF tidak terinstal."; pause ;;
            11)
                csf=$(get_csf_bin)
                if [[ -n "$csf" ]]; then
                    confirm_yn "Yakin flush SEMUA block?" && "$csf" -f || print_info "Dibatalkan."
                else print_error "CSF tidak terinstal."; fi
                pause ;;
            0) return ;;
            *) print_error "Pilihan salah."; pause ;;
        esac
    done
}

# =============================================================================
# 8 cPHulkd
# =============================================================================

manage_cphulk() {
    local sub list_name action ip comment rc
    clear
    sec_header "PENGELOLAAN cPHulk"
    if ! command -v whmapi1 &>/dev/null; then
        print_error "whmapi1 tidak ditemukan."; pause; return
    fi
    m 1 "Flush History Reports"
    m 2 "Tambah IP ke Whitelist"
    m 3 "Hapus IP dari Whitelist"
    m 4 "Tambah IP ke Blacklist"
    m 5 "Hapus IP dari Blacklist"
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih [0-5]: "${NC})" sub

    case $sub in
        2|3) list_name="white" ;;
        4|5) list_name="black" ;;
    esac
    case $sub in
        2|4) action="create" ;;
        3|5) action="delete" ;;
    esac

    case $sub in
        1) whmapi1 flush_cphulk_login_history &>/dev/null && print_ok "Berhasil." || print_error "Gagal." ;;
        2|3|4|5)
            read -r -p "$(echo -e ${CYAN}"IP atau CIDR: "${NC})" ip
            if validate_ip_cidr "$ip"; then
                rc=0
                if [[ "$action" == "create" ]]; then
                    read -r -p "$(echo -e ${CYAN}"Komentar (opsional): "${NC})" comment
                    if [[ -z "$comment" ]]; then
                        whmapi1 create_cphulk_record list_name="$list_name" ip="$ip" &>/dev/null || rc=$?
                    else
                        whmapi1 create_cphulk_record list_name="$list_name" ip="$ip" comment="$comment" &>/dev/null || rc=$?
                    fi
                else
                    whmapi1 delete_cphulk_record list_name="$list_name" ip="$ip" &>/dev/null || rc=$?
                fi
                [[ $rc -eq 0 ]] && print_ok "Berhasil." || print_error "Gagal (rc=$rc)."
            fi
            ;;
        0) return ;;
        *) print_error "Pilihan salah." ;;
    esac
    pause
}

# =============================================================================
# 9 CLAMAV
# =============================================================================

scan_clamav() {
    local mode="$1" custom_dir="$2"
    clear
    sec_header "SCAN VIRUS CLAMAV"

    local CLAMSCAN_PATH="" path
    for path in /usr/local/cpanel/3rdparty/bin/clamscan /usr/bin/clamscan /usr/local/bin/clamscan /bin/clamscan; do
        [[ -x "$path" ]] && { CLAMSCAN_PATH="$path"; break; }
    done

    if [[ -z "$CLAMSCAN_PATH" ]]; then
        print_error "ClamAV tidak ditemukan."
        if confirm_yn "Install cpanel-clamav?"; then
            /scripts/install_clamav 2>/dev/null
            for path in /usr/local/cpanel/3rdparty/bin/clamscan /usr/bin/clamscan; do
                [[ -x "$path" ]] && { CLAMSCAN_PATH="$path"; break; }
            done
            [[ -z "$CLAMSCAN_PATH" ]] && { print_error "Masih tidak ada."; pause; return; }
        else pause; return; fi
    fi

    local targets=() scan_type="" username user_num=0
    if [[ "$mode" == "all" ]]; then
        need_file "$USER_LIST" || { pause; return; }
        mapfile -t targets < "$USER_LIST"
        scan_type="Semua user"
    elif [[ "$mode" == "single" ]]; then
        pick_user username "Nomor user: " || { pause; return; }
        targets=("$username")
        scan_type="User $username"
    elif [[ "$mode" == "custom" ]]; then
        [[ -z "$custom_dir" ]] && { print_error "Path kosong."; pause; return; }
        targets=("$custom_dir")
        scan_type="Folder $custom_dir"
    fi

    local dry_run="false" remove_args=()
    confirm_yn "Mode dry-run?" && dry_run="true"
    confirm_yn "Hapus file terinfeksi? (default: scan-only)" && remove_args=(--remove)

    local log_file="/root/clamav_scan_$(date +%Y%m%d_%H%M%S).log"
    print_info "Scanning: $scan_type ..."
    if [[ ${#remove_args[@]} -gt 0 ]]; then
        print_warn "MODE: HAPUS terinfeksi."
    else
        print_info "MODE: Scan-only."
    fi

    local total=0 infected=0 target scan_dir exclude_opts d
    for target in "${targets[@]}"; do
        if [[ "$mode" == "custom" ]]; then scan_dir="$target"; else scan_dir="/home/$target"; fi
        [[ ! -d "$scan_dir" ]] && { print_warn "Skip $scan_dir"; continue; }
        ((total++))
        echo "Memproses: $scan_dir" | tee -a "$log_file"
        exclude_opts=""
        if [[ "$mode" != "custom" ]]; then
            local exclude_dirs=(cache tmp .cache .trash logs backup .cpanel .softaculous)
            for d in "${exclude_dirs[@]}"; do exclude_opts+=" --exclude-dir=$scan_dir/$d"; done
        fi
        if [[ "$dry_run" == "true" ]]; then
            if [[ ${#remove_args[@]} -gt 0 ]]; then
                echo "  DRY-RUN: $CLAMSCAN_PATH -v -r $exclude_opts --remove --infected --no-summary $scan_dir"
            else
                echo "  DRY-RUN: $CLAMSCAN_PATH -v -r $exclude_opts --infected --no-summary $scan_dir"
            fi
        else
            # shellcheck disable=SC2086
            stdbuf -oL "$CLAMSCAN_PATH" -v -r $exclude_opts "${remove_args[@]}" --infected --no-summary "$scan_dir" 2>&1 | \
                grep -v -E "LibClamAV: iconv error|LibClamAV: cli_scanhtml" | tee -a "$log_file"
            grep -q "FOUND" "$log_file" && ((infected++))
        fi
    done
    print_info "Selesai. Target: $total, Infeksi: $infected"
    print_info "Log: $log_file"
    pause
}

menu_scan_virus() {
    local sub custom
    while true; do
        clear
        sec_header "SCAN VIRUS CLAMAV"
        m 1 "Scan home user (all)"
        m 2 "Scan home user X"
        m 3 "Scan custom folder"
        m 0 "Kembali"
        read -r -p "$(echo -e ${CYAN}"Pilih [0-3]: "${NC})" sub
        case $sub in
            1) scan_clamav "all" ;;
            2) scan_clamav "single" ;;
            3)
                read -r -p "$(echo -e ${CYAN}"Path folder: "${NC})" custom
                [[ -d "$custom" ]] && scan_clamav "custom" "$custom" || { print_error "Folder tidak ditemukan."; pause; }
                ;;
            0) return ;;
            *) print_error "Pilihan salah"; pause ;;
        esac
    done
}

# =============================================================================
# 10 CEK RESOURCE (CACHE ps aux)
# =============================================================================

cek_resource() {
    clear
    sec_header "FULL SYSTEM MONITOR"
    echo ""
    echo -e "${CYAN}▶ Date/Time:${NC} $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}▶ Internet Status:${NC}"
    if ping -c 1 google.com &>/dev/null || ping -c 1 8.8.8.8 &>/dev/null; then
        echo -e "  ${GREEN}✓ Connected${NC}"
    else
        echo -e "  ${RED}✗ Disconnected${NC}"
    fi
    echo ""
    echo -e "${CYAN}▶ OS:${NC}"
    echo -e "  ${BOLD}Type:${NC} $(uname -o 2>/dev/null || echo Unknown)"
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release 2>/dev/null || true
        echo -e "  ${BOLD}Name:${NC} ${NAME:-Unknown}"
        echo -e "  ${BOLD}Version:${NC} ${VERSION:-Unknown}"
    fi
    echo -e "  ${BOLD}Kernel:${NC} $(uname -r)"
    echo -e "  ${BOLD}Hostname:${NC} $(hostname)"
    echo ""
    echo -e "${CYAN}▶ Memory:${NC}"
    free -h | grep -E '^Mem:' | while read -r line; do
        echo "  Total: $(echo "$line" | awk '{print $2}') | Used: $(echo "$line" | awk '{print $3}') | Available: $(echo "$line" | awk '{print $7}')"
    done
    echo ""
    echo -e "${CYAN}▶ Disk:${NC}"
    df -h | grep -E '^(Filesystem|/dev/)' | while read -r line; do
        if [[ "$line" == Filesystem* ]]; then echo "  $line"
        else
            usage=$(echo "$line" | awk '{print $5}' | sed 's/%//')
            if [[ $usage -gt 90 ]]; then color="$RED"; elif [[ $usage -gt 75 ]]; then color="$YELLOW"; else color="$GREEN"; fi
            echo -e "  $(echo "$line" | awk '{print $2, $3, $4}')  ${color}${usage}%${NC}  $(echo "$line" | awk '{print $6}')"
        fi
    done
    echo ""
    echo -e "${CYAN}▶ Load Average:${NC}"
    uptime | awk -F'load average:' '{print "  "$2}'
    echo ""

    # Cache ps aux satu kali
    local PS_CACHE
    PS_CACHE=$(ps aux --sort=-%cpu 2>/dev/null)

    echo -e "${CYAN}▶ Rootkit Detection:${NC}"
    local hidden_count=0
    while read -r pid; do
        if [[ ! -d "/proc/$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo -e "    ${RED}⚠️ Hidden PID: $pid${NC}"
            ((hidden_count++))
        fi
    done < <(ps -eo pid= | tail -500)
    [[ $hidden_count -eq 0 ]] && echo -e "    ${GREEN}✓ No hidden PIDs.${NC}"
    echo ""
    echo -e "${CYAN}▶ Top 10 CPU:${NC}"
    echo "$PS_CACHE" | head -11 | tail -10 | while read -r line; do
        local cpu=$(echo "$line" | awk '{print $3}') mem=$(echo "$line" | awk '{print $4}') cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | cut -c1-50)
        echo -e "  CPU: ${GREEN}${cpu}%${NC} MEM: ${BLUE}${mem}%${NC} ${cmd}"
    done
    echo ""
    echo -e "${CYAN}▶ Spam Processes:${NC}"
    local spam_count=$(echo "$PS_CACHE" | grep -E "exim|sendmail|mailq|php.*mail|perl.*mail" | grep -v "grep" | wc -l)
    if [[ $spam_count -gt 5 ]]; then
        echo -e "  ${RED}⚠️ High: $spam_count${NC}"
        echo "$PS_CACHE" | grep -E "exim|sendmail|mailq|php.*mail" | grep -v grep | head -5 | while read -r line; do
            echo -e "  ${YELLOW}$line${NC}"
        done
    else
        echo -e "  ${GREEN}✓ Normal: $spam_count${NC}"
    fi
    echo ""
    echo -e "${CYAN}▶ Critical Services:${NC}"
    local svc
    for svc in httpd mysql mariadb php-fpm exim dovecot named csf lfd; do
        ( systemctl is-active --quiet "$svc" 2>/dev/null || pgrep -x "$svc" &>/dev/null ) && echo -e "  ${GREEN}✓${NC} $svc"
    done
    echo ""
    pause
}

# =============================================================================
# 11 SEARCHING X — Score function (extracted)
# =============================================================================

_score_ws_file() {
    local file="$1"
    [[ -r "$file" ]] || return 0
    local score=0 reasons="" ext h
    ext="${file##*.}"; ext="${ext,,}"
    h=$(head -c 16 "$file" 2>/dev/null | od -An -tx1 | tr -d ' \n')

    case "$ext" in
        jpg|jpeg|png|gif|bmp|webp|ico|mp4|mp3|pdf|zip)
            [[ "$h" == 3c3f706870* || "$h" == 3c3f* ]] && { score=$((score+60)); reasons+="HIDDEN_PHP,"; } ;;
        php|phtml|inc|phar|php3|php4|php5|php7|php8)
            case "$h" in
                47494638*|89504e47*|ffd8ff*|424d*|504b0304*) score=$((score+55)); reasons+="POLYGLOT," ;;
            esac ;;
    esac

    case "$file" in
        *.php.*|*.phtml.*|*.php[0-9].*)
            case "$file" in
                *.jpg|*.jpeg|*.png|*.gif|*.txt|*.zip|*.pdf) score=$((score+40)); reasons+="DOUBLE_EXT," ;;
            esac ;;
    esac

    case "$file" in
        *.sorry|*.sorry_exist|*.encrypted|*.locked|*.crypted|*.enc) score=$((score+70)); reasons+="RANSOMWARE," ;;
        */HOW_TO_DECRYPT*|*/DECRYPT_INSTRUCTIONS*) score=$((score+70)); reasons+="RANSOMWARE_NOTE," ;;
    esac

    grep -qE 'c99shell|r57shell|wso\.php|b374k|Ninja-Shell|Gugi|hekerprotzy' "$file" 2>/dev/null && { score=$((score+60)); reasons+="SIGNATURE,"; }
    grep -qE '(eval|assert|system|exec|shell_exec|passthru)[[:space:]]*\([[:space:]]*[$]_COOKIE' "$file" 2>/dev/null && { score=$((score+50)); reasons+="COOKIE_EXEC,"; }

    if grep -qE 'password_verify[[:space:]]*\([[:space:]]*[$]_POST' "$file" 2>/dev/null && \
       grep -qE 'proc_open|base64_decode[[:space:]]*\([[:space:]]*base64_decode[[:space:]]*\([[:space:]]*base64_decode' "$file" 2>/dev/null; then
        score=$((score+40)); reasons+="FILEMANAGER,"
    fi

    local hi=0 hd=0 he=0
    grep -qE '\$_(GET|POST|COOKIE|REQUEST)[[:space:]]*\[' "$file" 2>/dev/null && hi=1
    grep -qE '(base64_decode|hex2bin|gzinflate|str_rot13|strrev)[[:space:]]*\(' "$file" 2>/dev/null && hd=1
    grep -qE '\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\(' "$file" 2>/dev/null && he=1
    if   [[ $hi -eq 1 && $hd -eq 1 && $he -eq 1 ]]; then score=$((score+80)); reasons+="FULL_SKELETON,"
    elif [[ $hi -eq 1 && $he -eq 1 ]]; then score=$((score+40)); reasons+="INPUT_EXEC,"
    fi
    grep -qE '(system|exec|shell_exec|passthru|eval|assert)[[:space:]]*\([[:space:]]*[$]_' "$file" 2>/dev/null && { score=$((score+30)); reasons+="COMBO,"; }

    [[ $score -ge 30 ]] && printf '%s\t%s\t%s\n' "$score" "$file" "$reasons"
}
export -f _score_ws_file

ROOTKIT_FINDINGS=0
HIDDEN_DOTFILES_COUNT=0

detect_rootkit_v2() {
    local log_file="$1"
    local hp=0 sm=0 pf=0
    {
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[0/5] ROOTKIT DETECTION"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "── Hidden PID ──"
        while read -r pid; do
            if [[ ! -d "/proc/$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                echo "  ⚠ Hidden PID: $pid"
                ((hp++))
            fi
        done < <(ps -eo pid= | sort -n | tail -500)
        [[ $hp -eq 0 ]] && echo "  ✓ No hidden PIDs"
        echo ""
        echo "── LD Preload ──"
        if [[ -f /etc/ld.so.preload ]]; then
            echo "  ⚠ /etc/ld.so.preload EXISTS:"
            sed 's/^/    /' /etc/ld.so.preload
            pf=1
        else echo "  ✓ /etc/ld.so.preload not found"; fi
        echo ""
        echo "── Kernel Modules ──"
        while read -r line; do
            [[ -z "$line" ]] && continue
            echo "  ⚠ Suspicious: $line"
            ((sm++))
        done < <(lsmod 2>/dev/null | grep -E "rootkit|hide|evil|backdoor|malware|suckit|knark|adore|phalanx|enye")
        [[ $sm -eq 0 ]] && echo "  ✓ No suspicious modules"
        echo ""
        echo "── Ringkasan ──"
        echo "  Hidden PIDs : $hp"
        echo "  LD_PRELOAD  : $pf"
        echo "  Suspicious  : $sm"
    } > >(tee -a "$log_file")
    wait
    ROOTKIT_FINDINGS=$((hp + pf + sm))
}

scan_hidden_dotfiles() {
    local scan_dir="$1" log_file="$2" count=0 user home_dir f
    {
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[5/5] HIDDEN FILES (dotfiles)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        if [[ -f "$USER_LIST" ]]; then
            while IFS= read -r user; do
                home_dir="/home/$user"
                [[ -d "$home_dir" ]] || continue
                while IFS= read -r f; do
                    [[ -n "$f" ]] && { echo "  📄 $f"; ((count++)); }
                done < <(find "$home_dir" -name ".*" -type f 2>/dev/null)
            done < "$USER_LIST"
        fi
        echo ""
        [[ $count -eq 0 ]] && echo "  ✓ No hidden dotfiles" || echo "  Total: $count"
    } > >(tee -a "$log_file")
    wait
    HIDDEN_DOTFILES_COUNT=$count
}

scan_phpshell() {
    local mode="$1" target_user="$2" full_scan="${3:-no}"
    clear
    echo -e "${BLUE}========== WEBSHELL SCANNER v3 (v9.0) ==========${NC}"
    echo ""
    if [[ "$full_scan" == "yes" ]]; then
        echo -e "${MAGENTA}MODE: FULL SECURITY SCAN${NC}"
        echo -e "${MAGENTA}      Rootkit + PHP + Hidden + Ransomware${NC}"
    else
        echo -e "${MAGENTA}MODE: PHP SCAN (FAST)${NC}"
    fi
    echo ""

    load_all_fingerprints

    local scan_dir scan_label
    if [[ "$mode" == "all" ]]; then
        scan_dir="/home"; scan_label="Semua user"
    else
        scan_dir="/home/$target_user"; scan_label="User $target_user"
        [[ ! -d "$scan_dir" ]] && { print_error "Tidak ditemukan: $scan_dir"; pause; return; }
    fi

    local log_file="/root/phpshell_scan_$(date +%Y%m%d_%H%M%S).log"
    local quarantine_tmp=$(mktemp)
    local critical_found=0 suspicious_found=0

    ROOTKIT_FINDINGS=0
    HIDDEN_DOTFILES_COUNT=0

    echo ""
    print_info "Target : $scan_label ($scan_dir)"
    print_info "Log    : $log_file"
    echo ""

    if [[ "$full_scan" == "yes" ]]; then
        print_info "[0/5] Rootkit..."
        detect_rootkit_v2 "$log_file"
        if [[ $ROOTKIT_FINDINGS -gt 0 ]]; then
            echo -e "      ${RED}⚠ $ROOTKIT_FINDINGS indikator${NC}"
        else
            echo -e "      ${GREEN}✓ Bersih${NC}"
        fi
        echo ""
    fi

    local t0=$(date +%s)
    local total_files=$(find "$scan_dir" -type f 2>/dev/null | wc -l)
    print_info "[1/5] Total file: $total_files"
    if [[ $total_files -eq 0 ]]; then
        print_warn "Tidak ada file."
        rm -f "$quarantine_tmp"
        pause; return
    fi

    print_info "[2/5] Pre-filter paralel (${WS_PARALLEL_JOBS} core)..."
    local prefilter=$(mktemp)
    local combined_pat='c99shell|r57shell|wso\.php|b374k|Ninja-Shell|Gugi|hekerprotzy|pwnkit|dirtypipe|linux-exploit-suggester|password_verify[[:space:]]*\([[:space:]]*[$]_POST|base64_decode[[:space:]]*\([[:space:]]*base64_decode[[:space:]]*\([[:space:]]*base64_decode|(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*[$]_COOKIE|isset[[:space:]]*\([[:space:]]*[$]_COOKIE|phpspy|litespeed_request_headers|imunify360_request_headers|chmodRecursive'

    find "$scan_dir" -type f \( \
        -name "*.php" -o -name "*.phtml" -o -name "*.phps" \
        -o -name "*.php3" -o -name "*.php4" -o -name "*.php5" \
        -o -name "*.php7" -o -name "*.php8" -o -name "*.inc" \
        -o -name "*.phar" -o -name "*.cgi" -o -name "*.pl" \
        -o -name "*.py" -o -name "*.sh" \
    \) -size -5M -print0 2>/dev/null | \
        xargs -0 -P "$WS_PARALLEL_JOBS" -I{} grep -lE "$combined_pat" {} 2>/dev/null >> "$prefilter" || true

    find "$scan_dir" -type f \( \
        -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" \
        -o -name "*.bmp" -o -name "*.webp" -o -name "*.ico" \
    \) -size -5M -print0 2>/dev/null | \
        xargs -0 -P "$WS_PARALLEL_JOBS" -I{} sh -c 'h=$(head -c 5 "$1" 2>/dev/null | od -An -tx1 | tr -d " \n"); case "$h" in 3c3f706870*|3c3f*) echo "$1";; esac' _ {} >> "$prefilter" 2>/dev/null || true

    find "$scan_dir" -type f -regextype posix-extended \
        -regex '.*\.(php|phtml|php[0-9])\.(jpg|png|gif|txt|zip|pdf)$' \
        -size -5M 2>/dev/null >> "$prefilter" || true

    find "$scan_dir" -type f \( \
        -name "*.sorry" -o -name "*.sorry_exist" -o -name "*.encrypted" \
        -o -name "*.locked" -o -name "*.crypted" -o -name "*.enc" \
        -o -name "HOW_TO_DECRYPT*" -o -name "DECRYPT_INSTRUCTIONS*" \
    \) 2>/dev/null >> "$prefilter" || true

    sort -u "$prefilter" -o "$prefilter"
    local prefilter_count=$(wc -l < "$prefilter")
    local elapsed=$(($(date +%s) - t0))
    print_info "      Kandidat: $prefilter_count dari $total_files (${elapsed}s)"

    if [[ $prefilter_count -eq 0 ]]; then
        print_ok "Tidak ada file mencurigakan."
        rm -f "$prefilter" "$quarantine_tmp"
        if [[ "$full_scan" == "yes" ]]; then
            echo ""
            print_info "[5/5] Hidden dotfile scan..."
            scan_hidden_dotfiles "$scan_dir" "$log_file"
        fi
        echo ""
        echo -e "${BLUE}═══════════ RINGKASAN ═══════════${NC}"
        [[ "$full_scan" == "yes" ]] && echo -e "Rootkit: ${GREEN}$ROOTKIT_FINDINGS${NC}"
        [[ "$full_scan" == "yes" ]] && echo "Hidden dotfiles: $HIDDEN_DOTFILES_COUNT"
        echo "Total: $total_files"
        echo -e "PHP threats: ${GREEN}0${NC}"
        echo "Log: $log_file"
        pause
        return
    fi

    print_info "[3/5] Detail scan paralel (${WS_PARALLEL_JOBS} core)..."
    t0=$(date +%s)
    local detail=$(mktemp)
    cat "$prefilter" | xargs -P "$WS_PARALLEL_JOBS" -I{} bash -c '_score_ws_file "$1"' _ {} >> "$detail" 2>/dev/null || true
    elapsed=$(($(date +%s) - t0))
    print_info "      Selesai (${elapsed}s)"

    print_info "[4/5] Laporan..."
    if [[ -s "$detail" ]]; then
        sort -t$'\t' -k1 -rn "$detail" -o "$detail"
        while IFS=$'\t' read -r score file reasons; do
            local threat="MEDIUM"
            if [[ $score -ge 80 ]]; then threat="CRITICAL"; ((critical_found++))
            elif [[ $score -ge 55 ]]; then threat="HIGH"; ((critical_found++))
            else ((suspicious_found++)); fi
            case "$threat" in
                CRITICAL) echo -e "${RED}💀 [$threat:$score] $file${NC}" ;;
                HIGH) echo -e "${YELLOW}⚠️  [$threat:$score] $file${NC}" ;;
                *) echo -e "${CYAN}🔍 [$threat:$score] $file${NC}" ;;
            esac
            echo -e "   ${MAGENTA}Reasons: $reasons${NC}"
            echo ""
            {
                echo "=== [$threat score=$score] $file"
                echo "Reasons: $reasons"
                echo "MD5: $(md5sum "$file" 2>/dev/null | awk '{print $1}')"
                echo ""
            } >> "$log_file"
            if [[ "$threat" == "CRITICAL" ]] || [[ "$threat" == "HIGH" ]]; then
                {
                    echo "───────────────────────────────────"
                    echo "PATH    : $file"
                    echo "LEVEL   : $threat"
                    echo "SCORE   : $score"
                    echo "REASONS : $reasons"
                    echo "ACTION  : chmod 000 '$file' && mv '$file' /root/quarantine/"
                    echo ""
                } >> "$quarantine_tmp"
            fi
        done < "$detail"
    fi
    rm -f "$prefilter" "$detail"

    if [[ "$full_scan" == "yes" ]]; then
        print_info "[5/5] Hidden dotfile scan..."
        scan_hidden_dotfiles "$scan_dir" "$log_file"
    fi

    echo ""
    echo -e "${BLUE}═══════════ RINGKASAN ═══════════${NC}"
    if [[ "$full_scan" == "yes" ]]; then
        if [[ $ROOTKIT_FINDINGS -gt 0 ]]; then
            echo -e "Rootkit: ${RED}$ROOTKIT_FINDINGS ⚠${NC}"
        else
            echo -e "Rootkit: ${GREEN}$ROOTKIT_FINDINGS${NC}"
        fi
        echo "Hidden dotfiles: $HIDDEN_DOTFILES_COUNT"
    fi
    echo "Total: $total_files"
    echo "Kandidat: $prefilter_count"
    echo -e "Critical: ${RED}$critical_found${NC}"
    echo -e "Suspicious: ${YELLOW}$suspicious_found${NC}"
    echo "Log: $log_file"

    if [[ -s "$quarantine_tmp" ]]; then
        {
            echo "═══════════════════════════════════════"
            echo "QUARANTINE RECOMMENDATIONS"
            echo "Generated: $(date)"
            echo "Source   : scan_phpshell v3 (whmcpanel v9.0)"
            echo "Mode     : $([[ "$full_scan" == "yes" ]] && echo "FULL SCAN" || echo "PHP ONLY")"
            echo "═══════════════════════════════════════"
            echo ""
            echo "LOG ONLY — tidak ada auto-action."
            echo "Review manual sebelum eksekusi."
            echo ""
            cat "$quarantine_tmp"
            echo ""
            echo "═══════════════════════════════════════"
        } > "$WS_QUARANTINE_FILE"
        rm -f "$quarantine_tmp"
        echo -e "${YELLOW}Quarantine: $WS_QUARANTINE_FILE${NC}"
    else
        rm -f "$quarantine_tmp"
    fi
    pause
}

menu_searching_x() {
    local sub username
    while true; do
        clear
        sec_header "SEARCHING X"
        m 1 "Full Security Scan ⚡ (Rootkit + PHP + Hidden + Ransomware)"
        m 2 "PHP Scan Per User (FAST)"
        m 3 "Cari Email Tertentu"
        m 4 "Cari Email by Subject"
        m 5 "Hapus Email Berdasarkan Waktu"
        m 6 "Analisis Detect Spam"
        m 7 "Spamming Email"
        m 8 "Cek IP Pengirim Spam"
        m 0 "Kembali"
        read -r -p "$(echo -e ${CYAN}"Pilih [0-8]: "${NC})" sub
        case $sub in
            1) scan_phpshell "all" "" "yes" ;;
            2)
                pick_user username "Nomor user: " || { pause; continue; }
                scan_phpshell "single" "$username" "no"
                ;;
            3) search_email ;;
            4) search_email_by_subject ;;
            5) delete_email_by_date ;;
            6) analyze_exim_spam ;;
            7) check_spamming_email ;;
            8) check_spamming_ip ;;
            0) return ;;
            *) print_error "Pilihan salah"; pause ;;
        esac
    done
}

# =============================================================================
# EMAIL
# =============================================================================

exim_report() {
    local mode="$1" log="${2:-/var/log/exim_mainlog}" top="${3:-20}"
    [[ -f "$log" ]] || { print_error "Log tidak ada: $log"; return 1; }
    case "$mode" in
        login)    awk '/_login:/{for(i=1;i<=NF;i++)if($i~/_login:/){split($i,a,":");print a[2]}}' "$log" | sort | uniq -c | sort -nr | head -"$top" ;;
        senders)  awk '/U=/{for(i=1;i<=NF;i++)if($i~/U=/){split($i,a,"=");print a[2]}}' "$log" | sort | uniq -c | sort -nr | head -"$top" ;;
        cwd)      awk '/cwd=\/home/{for(i=1;i<=NF;i++)if($i~/cwd=\/home/){print $i}}' "$log" | sed 's/cwd=//' | sort | uniq -c | sort -nr | head -"$top" ;;
        php)      grep "X-PHP-Script" "$log" 2>/dev/null | sed -n 's/.*X-PHP-Script: \([^ ]*\)/\1/p' | sort | uniq -c | sort -nr | head -"$top" ;;
        rejected) grep -E "rejected|blocked|spam" "$log" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort | uniq -c | sort -nr | head -"$top" ;;
        connect)  grep -E "connect from" "$log" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort | uniq -c | sort -nr | head -"$top" ;;
        authfail) grep -E "auth failed|login failed" "$log" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort | uniq -c | sort -nr | head -"$top" ;;
    esac
}

search_email() {
    local search_type email_addr search_pattern fc fd sd ed total current file status header
    local -a found=()
    clear
    sec_header "CARI EMAIL"
    m 1 "Pengirim (From)"
    m 2 "Penerima (To)"
    read -r -p "$(echo -e ${CYAN}"Pilih [1-2]: "${NC})" search_type
    case $search_type in
        1) read -r -p "$(echo -e ${CYAN}"Alamat pengirim: "${NC})" email_addr; search_pattern="From:.*$email_addr" ;;
        2) read -r -p "$(echo -e ${CYAN}"Alamat penerima: "${NC})" email_addr; search_pattern="To:.*$email_addr" ;;
        *) print_error "Pilihan salah"; pause; return ;;
    esac
    [[ -z "$email_addr" ]] && { print_error "Kosong"; pause; return; }

    fd=false
    if confirm_yn "Filter tanggal?"; then
        fd=true
        read -r -p "$(echo -e ${CYAN}"Tanggal mulai (YYYY-MM-DD): "${NC})" sd
        if [[ -z "$sd" ]] || ! date -d "$sd" >/dev/null 2>&1; then
            print_error "Invalid. Filter dibatalkan."; fd=false
        else
            read -r -p "$(echo -e ${CYAN}"Tanggal akhir (kosong = hari ini): "${NC})" ed
            [[ -z "$ed" ]] && ed=$(date -d "+1 day" +%Y-%m-%d)
        fi
    fi

    if [[ "$fd" == true ]]; then
        total=$(find /home/*/mail/ -type f -newermt "$sd" ! -newermt "$ed" 2>/dev/null | wc -l)
    else
        total=$(find /home/*/mail/ -type f 2>/dev/null | wc -l)
    fi
    [[ $total -eq 0 ]] && { print_warn "Tidak ada email."; pause; return; }

    current=0
    if [[ "$fd" == true ]]; then
        while IFS= read -r file; do
            ((current++)); progress_bar "$current" "$total"
            grep -q "$search_pattern" "$file" 2>/dev/null && found+=("$file")
        done < <(find /home/*/mail/ -type f -newermt "$sd" ! -newermt "$ed" 2>/dev/null)
    else
        while IFS= read -r file; do
            ((current++)); progress_bar "$current" "$total"
            grep -q "$search_pattern" "$file" 2>/dev/null && found+=("$file")
        done < <(find /home/*/mail/ -type f 2>/dev/null)
    fi
    echo ""

    [[ ${#found[@]} -eq 0 ]] && { print_warn "Tidak ditemukan."; pause; return; }
    echo "Hasil (${#found[@]}):"
    local f
    for f in "${found[@]}"; do
        [[ "$f" == *"/new/"* ]] && status="NEW" || status="CUR"
        header=$(grep -m1 -E "^From:|^To:" "$f" 2>/dev/null | head -1)
        echo "File: $f"
        echo "Status: $status"
        echo "Header: $header"
        echo "----"
    done
    pause
}

search_email_by_subject() {
    local kw total current file status sl
    local -a found=()
    clear
    sec_header "CARI EMAIL BY SUBJECT"
    read -r -p "$(echo -e ${CYAN}"Kata kunci: "${NC})" kw
    [[ -z "$kw" ]] && { print_error "Kosong"; pause; return; }
    total=$(find /home/*/mail/ -type f 2>/dev/null | wc -l)
    [[ $total -eq 0 ]] && { print_warn "Tidak ada email."; pause; return; }
    current=0
    while IFS= read -r file; do
        ((current++)); progress_bar "$current" "$total"
        grep -q -i "Subject:.*$kw" "$file" 2>/dev/null && found+=("$file")
    done < <(find /home/*/mail/ -type f 2>/dev/null)
    echo ""
    [[ ${#found[@]} -eq 0 ]] && { print_warn "Tidak ditemukan."; pause; return; }
    echo "Ditemukan ${#found[@]}:"
    local f
    for f in "${found[@]}"; do
        [[ "$f" == *"/new/"* ]] && status="NEW" || status="CUR"
        sl=$(grep -i "^Subject:" "$f" 2>/dev/null | head -1)
        echo "File: $f"
        echo "Status: $status"
        echo "Subject: $sl"
        echo "----"
    done
    echo ""
    echo -e "${YELLOW}PERHATIAN: Aksi berikut MENGHAPUS SEMUA file di atas.${NC}"
    confirm_yn "Hapus semua?" && { rm -f "${found[@]}" 2>/dev/null; print_ok "Selesai."; } || print_info "Tidak ada yang dihapus."
    pause
}

delete_email_by_date() {
    local tc et year month mp sd ey em emp ed count total_size
    local -a find_args=()
    clear
    sec_header "HAPUS EMAIL BERDASARKAN WAKTU"
    m 1 "Incoming"
    m 2 "Outgoing"
    read -r -p "$(echo -e ${CYAN}"Pilih [1-2]: "${NC})" tc
    case $tc in
        1) et="incoming" ;;
        2) et="outgoing" ;;
        *) print_error "Pilihan salah"; pause; return ;;
    esac
    read -r -p "$(echo -e ${CYAN}"Tahun (YYYY): "${NC})" year
    [[ ! $year =~ ^[0-9]{4}$ ]] && { print_error "Tahun salah."; pause; return; }
    read -r -p "$(echo -e ${CYAN}"Bulan (1-12): "${NC})" month
    if [[ ! $month =~ ^[0-9]+$ ]] || (( month < 1 || month > 12 )); then
        print_error "Bulan salah."; pause; return
    fi
    mp=$(printf "%02d" "$month")
    sd="$year-$mp-01"
    if [ "$month" -eq 12 ]; then ey=$((year+1)); em=01; else ey=$year; em=$((month+1)); fi
    emp=$(printf "%02d" "$em")
    ed="$ey-$emp-01"

    print_info "Mencari $et dari $sd sampai (sebelum) $ed ..."
    if [ "$et" = "incoming" ]; then
        find_args=(/home -type f \( -path "*/mail/*/*/cur/*" -o -path "*/mail/*/*/new/*" \) -newermt "$sd" ! -newermt "$ed")
    else
        find_args=(/home -type f \( -path "*/mail/*/*/.Sent/cur/*" -o -path "*/mail/*/*/.Sent/new/*" -o -path "*/mail/*/*/Sent/cur/*" -o -path "*/mail/*/*/Sent/new/*" \) -newermt "$sd" ! -newermt "$ed")
    fi
    read count total_size <<< "$(find "${find_args[@]}" -printf "%s\n" 2>/dev/null | awk '{sum+=$1; count++} END {print count, sum}')"
    if [ -z "$count" ] || [ "$count" -eq 0 ]; then
        print_warn "Tidak ada email."; pause; return
    fi
    echo -e "${GREEN}Total: $count${NC}"
    echo -e "${GREEN}Ukuran: $(human_size "$total_size")${NC}"
    confirm_yn "Dry-run dulu?" Y && { echo "=== DRY-RUN ==="; find "${find_args[@]}" -printf "%p\n" 2>/dev/null | head -10; pause; return; }
    confirm_yn "Yakin hapus SEMUA $count email?" || { print_info "Dibatalkan."; pause; return; }
    find "${find_args[@]}" -exec rm -f {} + 2>/dev/null
    local rem=$(find "${find_args[@]}" -printf "." 2>/dev/null | wc -c)
    [ "$rem" -eq 0 ] && print_info "Selesai." || print_warn "Sisa $rem file."
    pause
}

analyze_exim_spam() {
    local log="/var/log/exim_mainlog" top=10 input out
    clear
    sec_header "ANALISIS EXIM"
    [[ ! -f "$log" ]] && { print_error "Log tidak ada."; pause; return; }
    read -r -p "$(echo -e ${CYAN}"Top N [10]: "${NC})" input
    [[ -n "$input" && "$input" =~ ^[0-9]+$ ]] && top=$input
    out="/root/exim_analysis_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "Analisis Exim - $(date)"
        echo "TOP SMTP LOGIN"
        exim_report login "$log" "$top"
        echo -e "\nTOP SENDERS"
        exim_report senders "$log" "$top"
        echo -e "\nTOP USER (cwd)"
        exim_report cwd "$log" "$top"
        echo -e "\nTOP PHP SCRIPTS"
        exim_report php "$log" "$top"
    } > "$out"
    cat "$out"
    print_info "Hasil: $out"
    pause
}

check_spamming_email() {
    local log="/var/log/exim_mainlog" out="/root/spam_email.log"
    print_info "Analisis aktivitas email..."
    {
        echo "===== TOP USER/HOME (cwd=/home) ====="
        exim_report cwd "$log" 20
        echo ""
        echo "===== TOP SENDERS (U=) ====="
        exim_report senders "$log" 20
        echo ""
        echo "===== TOP PHP SCRIPTS ====="
        exim_report php "$log" 20
    } > "$out"
    print_info "Hasil: $out"
    cat "$out"
    pause
}

check_spamming_ip() {
    local log="/var/log/exim_mainlog" out="/root/spam_ip.log"
    print_info "Analisis IP spam..."
    {
        echo "===== REJECTED/BLOCKED/SPAM ====="
        exim_report rejected "$log" 20
        echo ""
        echo "===== CONNECTION ATTEMPTS ====="
        exim_report connect "$log" 20
        echo ""
        echo "===== AUTH FAILURES ====="
        exim_report authfail "$log" 20
    } > "$out"
    print_info "Hasil: $out"
    cat "$out"
    pause
}

# =============================================================================
# 12-13 CRONTAB
# =============================================================================

show_all_crontabs() {
    local username
    clear
    sec_header "SEMUA CRONTAB USER"
    while IFS=: read -r username _; do
        echo -e "${BLUE}----${NC}"
        echo "Crontab: $username"
        crontab -u "$username" -l 2>/dev/null || echo "  (tidak ada / akses ditolak)"
    done < /etc/passwd
    pause
}

dump_all_crontabs() {
    local cron_dir="/var/spool/cron" out cronfile user
    clear
    sec_header "DUMP CRONTAB"
    [[ ! -d "$cron_dir" ]] && { print_error "Direktori tidak ada."; pause; return; }
    out="/root/cronlist_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "===== DAFTAR CRONTAB ====="
        echo "Tanggal: $(date)"
        echo "Host: $(hostname -f)"
        for cronfile in "$cron_dir"/*; do
            if [[ -f "$cronfile" ]]; then
                user=$(basename "$cronfile")
                echo ""
                echo "### CRONTAB: $user ###"
                cat "$cronfile"
            fi
        done
    } > "$out"
    print_info "File: $out"
    pause
}

# =============================================================================
# 14 FIX PERMISSION
# =============================================================================

set_perms() {
    local target="$1" user="$2" group="${3:-$user}"
    [[ ! -e "$target" ]] && return 1
    [[ -d "$target" ]] || return 0
    find "$target" -type d -print0 2>/dev/null | while IFS= read -r -d '' dir; do chmod 755 "$dir" 2>/dev/null || true; done
    find "$target" -type f -print0 2>/dev/null | while IFS= read -r -d '' file; do chmod 644 "$file" 2>/dev/null || true; done
    find "$target" -type f \( -name "*.cgi" -o -name "*.pl" \) -print0 2>/dev/null | while IFS= read -r -d '' script; do chmod 755 "$script" 2>/dev/null || true; done
    chown -R "$user:$group" "$target" 2>/dev/null || true
}

fix_one_account() {
    local account="$1" homedir="/home/$1" pubdir="/home/$1/public_html" docroot
    [[ ! -d "$homedir" ]] && { print_error "Home $homedir tidak ada."; return 1; }
    print_info "Fix: $account"
    if [[ -d "$pubdir" ]]; then
        set_perms "$pubdir" "$account" "$account"
        chown "$account:nobody" "$pubdir" 2>/dev/null || true
        chmod 750 "$pubdir" 2>/dev/null || true
    else
        print_warn "public_html tidak ada."
    fi
    local userdata="/var/cpanel/userdata/$account"
    if [[ -d "$userdata" ]]; then
        grep -i "document" "$userdata"/* 2>/dev/null | awk -F: '{print $2}' | grep -v "public_html" | while read -r docroot; do
            docroot=$(echo "$docroot" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [[ -n "$docroot" && -d "$docroot" ]] && set_perms "$docroot" "$account" "$account"
        done
    fi
    print_ok "Selesai: $account"
}

fix_all_accounts() {
    local accounts ok=0 fail=0 inval="" acc tmp
    print_info "Proses semua akun..."
    if [[ -f "$USER_LIST" && -s "$USER_LIST" ]]; then accounts=$(cat "$USER_LIST")
    else accounts=$(ls /home 2>/dev/null | grep -v -E '^(virtfs|cpanel|clamav|cPanelInstall|0_README_BEFORE_DELETING_VIRTFS)$')
    fi
    for acc in $accounts; do
        if [[ -d "/home/$acc" ]]; then
            if fix_one_account "$acc"; then
                ok=$((ok+1))
            else
                fail=$((fail+1))
            fi
        else
            print_warn "Skip $acc (no home)"
            inval+=" $acc"
        fi
    done
    print_info "Berhasil: $ok, Gagal: $fail"
    if [[ -n "$inval" ]] && [[ -f "$USER_LIST" ]]; then
        confirm_yn "Hapus user invalid dari $USER_LIST?" && {
            tmp=$(mktemp)
            local u
            for u in $inval; do grep -v "^$u$" "$USER_LIST" > "$tmp"; mv "$tmp" "$USER_LIST"; done
        }
    fi
}

fix_permission() {
    local target username
    clear
    sec_header "FIX PERMISSION"
    m 1 "Satu user"
    m 2 "Semua user"
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih [0-2]: "${NC})" target
    case $target in
        0) return ;;
        1) pick_user username "Nomor atau username: " || { pause; return; }; fix_one_account "$username" ;;
        2) fix_all_accounts ;;
        *) print_error "Pilihan salah"; pause; return ;;
    esac
    pause
}

# =============================================================================
# 15 CLEAN LOG
# =============================================================================

clean_user_logs() {
    local quiet=false
    [[ "${1:-}" == "--quiet" ]] && quiet=true
    if [[ "$quiet" == false ]]; then
        clear
        sec_header "BERSIHKAN LOG USER"
        need_file "$USER_LIST" || { pause; return; }
    fi
    local gz=0 lg=0 i user logs_dir cg cl
    local -a users=()
    mapfile -t users < "$USER_LIST"
    local total=${#users[@]}
    for i in "${!users[@]}"; do
        user="${users[$i]}"
        logs_dir="/home/$user/logs"
        if [[ -d "$logs_dir" ]]; then
            cg=$(find "$logs_dir" -maxdepth 1 -type f -name "*.gz" 2>/dev/null | wc -l)
            [[ $cg -gt 0 ]] && { find "$logs_dir" -maxdepth 1 -type f -name "*.gz" -delete 2>/dev/null; ((gz += cg)); }
            cl=$(find "$logs_dir" -maxdepth 1 -type f -name "*.log" 2>/dev/null | wc -l)
            [[ $cl -gt 0 ]] && { find "$logs_dir" -maxdepth 1 -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null; ((lg += cl)); }
        fi
        progress_bar $((i+1)) "$total"
    done
    echo ""
    print_info "Selesai. .gz: $gz, .log: $lg"
    [[ "$quiet" == false ]] && pause
}

clean_server_logs() {
    local quiet=false
    [[ "${1:-}" == "--quiet" ]] && quiet=true
    if [[ "$quiet" == false ]]; then
        clear
        sec_header "PEMBERSIHAN LOG SERVER"
        confirm_yn "Lanjutkan?" || { print_info "Dibatalkan."; pause; return; }
    fi
    truncate_safe() { [[ -f "$1" ]] && { truncate -s 0 "$1" 2>/dev/null || echo -n > "$1" 2>/dev/null; }; }
    if [[ -d "/var/log/apache2" ]]; then
        local lf
        for lf in access_log error_log modsec_audit.log modsec_debug.log suexec_log suphp_log; do truncate_safe "/var/log/apache2/$lf"; done
    elif [[ -d "/etc/httpd/logs" ]]; then
        truncate_safe "/etc/httpd/logs/access_log"
        truncate_safe "/etc/httpd/logs/error_log"
    fi
    local lf
    for lf in access_log incoming_http_requests.log api_tokens_log license_log login_log panic_log cpbackup_transporter.log session_log cpwrapd_log; do
        truncate_safe "/usr/local/cpanel/logs/$lf"
    done
    find /var/log -type f \( -name "*.log.*" -o -name "*.log.gz" \) -delete 2>/dev/null
    find /usr/local/cpanel/logs -type f \( -name "*.log.*" -o -name "*.log.gz" \) -delete 2>/dev/null
    local syslog size
    for syslog in /var/log/messages /var/log/secure /var/log/maillog; do
        if [[ -f "$syslog" ]]; then
            size=$(stat -c%s "$syslog" 2>/dev/null || echo 0)
            [[ $size -gt 5242880 ]] && truncate_safe "$syslog"
        fi
    done
    print_info "Selesai."
    [[ "$quiet" == false ]] && pause
}

clean_virtfs() {
    local quiet=false
    [[ "${1:-}" == "--quiet" ]] && quiet=true
    print_info "Membersihkan VirtFS..."
    /scripts/clear_orphaned_virtfs_mounts
    print_info "Selesai."
    [[ "$quiet" == false ]] && pause
}

clean_frozen_email() {
    local quiet=false
    [[ "${1:-}" == "--quiet" ]] && quiet=true
    print_info "Menghapus frozen email..."
    exim -bp 2>/dev/null | grep frozen | awk '{print $3}' | xargs -r exim -Mrm
    print_info "Selesai."
    [[ "$quiet" == false ]] && pause
}

clean_cache() {
    local quiet=false
    [[ "${1:-}" == "--quiet" ]] && quiet=true
    print_info "Membersihkan cache..."
    if command -v dnf &>/dev/null; then dnf clean all 2>/dev/null; else yum clean all 2>/dev/null; fi
    rm -rf /var/cpanel/cache/* 2>/dev/null
    [[ -x /scripts/update_cache ]] && /scripts/update_cache 2>/dev/null
    print_info "Selesai."
    [[ "$quiet" == false ]] && pause
}

menu_clean_log_server() {
    local sub
    while true; do
        clear
        sec_header "CLEAN LOG SERVER"
        m 1 "Log User"
        m 2 "Log Server (Apache/cPanel/sistem)"
        m 3 "Clean Jail (VirtFS)"
        m 4 "Clean Frozen Email"
        m 5 "Clean Cache"
        m 6 "Clean All"
        m 0 "Kembali"
        read -r -p "$(echo -e ${CYAN}"Pilih [0-6]: "${NC})" sub
        case $sub in
            1) clean_user_logs ;;
            2) clean_server_logs ;;
            3) clean_virtfs ;;
            4) clean_frozen_email ;;
            5) clean_cache ;;
            6)
                print_info "Clean All..."
                clean_user_logs --quiet
                clean_server_logs --quiet
                clean_virtfs --quiet
                clean_frozen_email --quiet
                clean_cache --quiet
                print_info "Selesai."
                pause
                ;;
            0) return ;;
            *) print_error "Pilihan salah"; pause ;;
        esac
    done
}

# =============================================================================
# 16 MAKECACHE
# =============================================================================

makecache_update() {
    print_info "Makecache & upgrade..."
    if command -v dnf &>/dev/null; then
        dnf makecache -y && dnf upgrade -y
    else
        yum makecache -y && yum update -y
    fi
    print_info "Selesai."
    pause
}

# =============================================================================
# 17 SERVICES (optimized — skip systemctl status untuk pattern match)
# =============================================================================

manage_services() {
    local svc base is_std k service_name php_units unit act php_choice restart_apache
    clear
    sec_header "MANAJEMEN SERVICE"
    echo -e "${CYAN}Active Services:${NC}"
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        base="${svc%.service}"
        is_std=0
        for k in "${!KNOWN_SERVICES[@]}"; do
            [[ "$base" == "$k" ]] || [[ "$base" == *"$k"* ]] && { is_std=1; break; }
        done
        if [[ $is_std -eq 1 ]]; then
            echo -e "  ${GREEN}✓${NC} $svc"
        elif [[ "$base" =~ ^(cpanel|whm|cpd|cp-|cp_|cpdav|cpwrap|cphulk|cpsrvd|cpbackup|cpdavd|cpwrapd|cpcleanup|cpdovecot|cpapache) ]]; then
            echo -e "  ${BLUE}ℹ${NC} $svc (cPanel-like)"
        elif systemctl status "$svc" 2>/dev/null | grep -q "/usr/local/cpanel"; then
            echo -e "  ${BLUE}ℹ${NC} $svc (cPanel)"
        else
            echo -e "  ${RED}⚠${NC} UNKNOWN: $svc"
        fi
    done < <(systemctl list-units --type=service --state=running --no-pager --plain --no-legend 2>/dev/null | awk '{print $1}')

    echo ""
    m 1 "Apache"
    m 2 "Database"
    m 3 "Named"
    m 4 "Dovecot"
    m 5 "Exim"
    m 6 "SSH"
    m 7 "PHP-FPM"
    m 8 "Show Non-Standar"
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih [0-8]: "${NC})" svc

    if [[ "$svc" == "8" ]]; then
        while IFS= read -r line; do
            base="${line%.service}"
            is_std=0
            for k in "${!KNOWN_SERVICES[@]}"; do
                [[ "$base" == "$k" ]] || [[ "$base" == *"$k"* ]] && { is_std=1; break; }
            done
            if [[ $is_std -eq 0 ]] && [[ ! "$base" =~ ^(cpanel|whm|cpd|cp-|cp_) ]] && ! systemctl status "$line" 2>/dev/null | grep -q "/usr/local/cpanel"; then
                echo "  $line"
                systemctl status "$line" --no-pager | head -3
                echo ""
            fi
        done < <(systemctl list-units --type=service --state=running --no-pager --plain --no-legend 2>/dev/null | awk '{print $1}')
        pause; return
    fi

    case $svc in
        1) service_name="httpd" ;;
        2) systemctl is-active --quiet mariadb 2>/dev/null && service_name="mariadb" || service_name="mysqld" ;;
        3) service_name="named" ;;
        4) service_name="dovecot" ;;
        5) service_name="exim" ;;
        6) service_name="sshd" ;;
        7)
            php_units=""
            while IFS= read -r unit; do php_units+=" $unit"; done <<< "$(systemctl list-units --type=service --state=running --all 2>/dev/null | grep -E 'php-fpm-[0-9]+\.service' | awk '{print $1}')"
            set -- $php_units
            php_units=("$@")
            if [[ ${#php_units[@]} -gt 0 ]]; then
                echo "PHP-FPM services:"
                local i
                for i in "${!php_units[@]}"; do printf "%3d. %s\n" $((i+1)) "${php_units[$i]}"; done
                echo "  0. Semua"
                read -r -p "$(echo -e ${CYAN}"Pilih: "${NC})" php_choice
                if [[ "$php_choice" == "0" ]]; then service_name="php_fpm_all"
                elif [[ "$php_choice" =~ ^[0-9]+$ ]] && (( php_choice >= 1 && php_choice <= ${#php_units[@]} )); then
                    service_name="${php_units[$((php_choice-1))]}"
                else print_error "Pilihan salah."; pause; return; fi
            else
                print_warn "Tidak ada PHP-FPM."
                confirm_yn "Restart Apache?" && service_name="httpd" || { pause; return; }
            fi
            ;;
        0) return ;;
        *) echo "Pilihan salah"; return ;;
    esac
    echo "Aksi: 1=stop, 2=start, 3=restart"
    read -r -p "$(echo -e ${CYAN}"Pilih [1-3]: "${NC})" act
    case $act in
        1) [[ "$service_name" == "php_fpm_all" ]] && /scripts/restartsrv_php_fpm --stop || systemctl stop "$service_name" ;;
        2) [[ "$service_name" == "php_fpm_all" ]] && /scripts/restartsrv_php_fpm --start || systemctl start "$service_name" ;;
        3) [[ "$service_name" == "php_fpm_all" ]] && /scripts/restartsrv_php_fpm || systemctl restart "$service_name" ;;
        *) echo "Pilihan salah"; return ;;
    esac
    print_info "Selesai."
    pause
}

# =============================================================================
# 18 MYSQL
# =============================================================================

mysql_repair_optimize() {
    local opt db table inst
    clear
    sec_header "MYSQL MAINTENANCE"
    m 1 "Check & auto-repair"
    m 2 "Repair semua"
    m 3 "Optimize semua"
    m 4 "Optimize per tabel"
    m 5 "Tuning"
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih [0-5]: "${NC})" opt
    case $opt in
        1) mysqlcheck --check --auto-repair --all-databases ;;
        2) mysqlcheck -r --all-databases ;;
        3) mysqlcheck -o --all-databases ;;
        4)
            for db in $(mysql -e "show databases" | grep -v Database | grep -v information_schema | grep -v performance_schema | grep -v mysql); do
                print_info "Optimize $db"
                mysql "$db" -e "show tables" | grep -v Tables_in | grep -v "+" | while read -r table; do
                    mysql "$db" -e "optimize table $table" 2>/dev/null
                done
            done
            ;;
        5)
            if ! command -v mysqltuner &>/dev/null; then
                confirm_yn "Install mysqltuner?" && {
                    rpm -q epel-release &>/dev/null || install_package epel-release
                    install_package mysqltuner
                }
            fi
            command -v mysqltuner &>/dev/null && mysqltuner || echo "mysqltuner tidak tersedia"
            ;;
        0) return ;;
        *) echo "Pilihan salah"; pause; return ;;
    esac
    pause
}

# =============================================================================
# 19 APACHE TUNING
# =============================================================================

apache_tuning() {
    clear
    set +e
    local APACHE_BIN="" x
    for x in /usr/sbin/httpd /usr/sbin/apache2 /usr/local/apache/bin/httpd; do
        [ -x "$x" ] && { APACHE_BIN="$x"; break; }
    done
    [ -z "$APACHE_BIN" ] && APACHE_BIN=$(command -v httpd 2>/dev/null || command -v apache2 2>/dev/null)
    if [ -z "$APACHE_BIN" ]; then
        print_error "Apache binary tidak ditemukan."
        pause; return
    fi

    local APACHE_VERSION=$("$APACHE_BIN" -v 2>/dev/null | head -n 1)
    local SERVER_MPM=$("$APACHE_BIN" -V 2>/dev/null | awk -F': ' '/Server MPM:/ {print $2; exit}')
    [ -z "$SERVER_MPM" ] && SERVER_MPM="unknown"

    local TOTAL_MB AVAILABLE_MB SWAP_TOTAL_MB SWAP_USED_MB
    read -r TOTAL_MB _ _ _ _ AVAILABLE_MB <<< $(free -m | awk '/^Mem:/ {print $2, $3, $4, $5, $6, $7}')
    SWAP_TOTAL_MB=$(free -m | awk '/^Swap:/ {print $2}')
    SWAP_USED_MB=$(free -m | awk '/^Swap:/ {print $3}')
    TOTAL_MB="${TOTAL_MB:-0}"; AVAILABLE_MB="${AVAILABLE_MB:-0}"
    SWAP_TOTAL_MB="${SWAP_TOTAL_MB:-0}"; SWAP_USED_MB="${SWAP_USED_MB:-0}"

    local CPU_CORES=$(nproc 2>/dev/null || echo 1)
    local LOAD1=$(awk '{print $1}' /proc/loadavg)

    local APACHE_STATS=$(ps -eo comm=,rss= 2>/dev/null | awk '$1 ~ /^(httpd|apache2)$/ {c++; t+=$2; if($2>m)m=$2} END {printf "%d %d %d\n", c, t/1024, m/1024}')
    local APACHE_COUNT APACHE_RSS_TOTAL APACHE_RSS_MAX
    read -r APACHE_COUNT APACHE_RSS_TOTAL APACHE_RSS_MAX <<< "$APACHE_STATS"

    local AVG_APACHE_MB=0
    [[ $APACHE_COUNT -gt 0 ]] && AVG_APACHE_MB=$((APACHE_RSS_TOTAL / APACHE_COUNT))
    [[ $AVG_APACHE_MB -lt 1 ]] && AVG_APACHE_MB=1

    local RESERVE_MB=2048
    local TUNING_BUDGET_MB=$((AVAILABLE_MB - RESERVE_MB))
    [[ $TUNING_BUDGET_MB -lt 0 ]] && TUNING_BUDGET_MB=0

    local RECOMMENDED_WORKERS=0
    [[ $AVG_APACHE_MB -gt 0 ]] && RECOMMENDED_WORKERS=$((TUNING_BUDGET_MB / (AVG_APACHE_MB * 12 / 10)))
    [[ $RECOMMENDED_WORKERS -lt 10 && $AVG_APACHE_MB -gt 0 ]] && RECOMMENDED_WORKERS=10
    local MAX_REASONABLE=$((CPU_CORES * 100))
    [[ $RECOMMENDED_WORKERS -gt $MAX_REASONABLE ]] && RECOMMENDED_WORKERS=$MAX_REASONABLE

    echo ""
    echo -e "${CYAN}WHM/cPanel Apache Tuning Auditor v1.0${NC}"
    echo "Date : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Host : $(hostname -f 2>/dev/null || hostname)"
    echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
    echo "Apache version : $APACHE_VERSION"
    echo "Apache MPM     : $SERVER_MPM"
    echo "CPU cores      : $CPU_CORES"
    echo "Load average   : $LOAD1"
    echo ""
    echo "Total RAM      : ${TOTAL_MB} MB"
    echo "Available RAM  : ${AVAILABLE_MB} MB"
    echo "Swap total     : ${SWAP_TOTAL_MB} MB"
    echo "Swap used      : ${SWAP_USED_MB} MB"
    echo ""
    echo "Apache processes: $APACHE_COUNT"
    echo "Apache RSS total: ${APACHE_RSS_TOTAL} MB"
    echo "Avg Apache RSS  : ${AVG_APACHE_MB} MB"
    echo ""
    echo "Recommended Apache workers: ~$RECOMMENDED_WORKERS"
    if [[ "$SERVER_MPM" == *"prefork"* ]]; then
        echo "  MaxRequestWorkers: ~$RECOMMENDED_WORKERS"
        echo "  ServerLimit      : ~$RECOMMENDED_WORKERS"
        echo "  StartServers     : ~$((RECOMMENDED_WORKERS / 4))"
    elif [[ "$SERVER_MPM" == *"event"* ]] || [[ "$SERVER_MPM" == *"worker"* ]]; then
        echo "  MaxRequestWorkers: ~$RECOMMENDED_WORKERS"
        echo "  ThreadsPerChild  : 25 (default)"
    fi
    echo ""
    echo "IMPORTANT: AUDIT ONLY."
    pause
}

# =============================================================================
# 20 AUTOFIX WHM
# =============================================================================

autofix_whm() {
    local choice cmd
    local fixes=(fixsubdomainlogs fixtar fixvaliases resetquotas forcelocaldomain
        autorepair builddovecotconf buildeximconf buildhttpdconf httpspamdetect
        buildnsdconf cleanbyteslogs cleandns cleanmsglog cleanphpsessions cleanquotas
        cleansessions cleanupcheck clear_orphaned_virtfs_mounts mailperm setup_whmxfer_db
        optimize_eximstats patcheximconf enable_sqloptimizer update_db_cache
        update_exim_rejects update_mailman_cache updatenameserverips updatenow
        updatephpconf quota_auto_fix updatesigningkey updateuserdatacache
        find_and_fix_rpm_issues fixadmin fixheaders)
    clear
    sec_header "AUTOFIX WHM"
    echo "Pilih nomor atau 'all':"
    local i
    for i in "${!fixes[@]}"; do printf "%3d. %s\n" $((i+1)) "${fixes[$i]}"; done
    m 0 "Kembali"
    read -r -p "$(echo -e ${CYAN}"Pilih: "${NC})" choice
    if [[ "$choice" == "all" ]]; then
        for cmd in "${fixes[@]}"; do print_info "/scripts/$cmd"; /scripts/"$cmd"; done
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#fixes[@]} ]; then
        cmd="${fixes[$((choice-1))]}"
        print_info "/scripts/$cmd"
        /scripts/"$cmd"
    elif [[ "$choice" == "0" ]]; then
        return
    else
        print_error "Pilihan tidak valid."
    fi
    pause
}

# =============================================================================
# 21 EKSTRAK DNS
# =============================================================================

extract_dns() {
    local zona_files zona domain ip
    clear
    sec_header "EKSTRAK DOMAIN & IP A RECORD"
    zona_files=$(find /var/named -type f \( -name "*.db" -o -name "*.zone" \) ! -name "*.bak" 2>/dev/null)
    [[ -z $zona_files ]] && { print_error "Tidak ada file zona."; pause; return; }
    echo "Domain dan IP A Record:"
    for zona in $zona_files; do
        domain=$(basename "$zona" | sed -E 's/\.(db|zone)$//')
        ip=$(grep -E '^[^;]*\s+IN\s+A\s+' "$zona" | head -1 | awk '{print $NF}')
        [[ -n $ip ]] && echo "$domain -> $ip"
    done
    pause
}

# =============================================================================
# MENU UTAMA v9.0
# =============================================================================

main_menu() {
    local choice
    while true; do
        clear
        echo -e "${BLUE}==================================================${NC}"
        echo -e "${CYAN}        WHM/cPanel Management Script v9.0         ${NC}"
        echo -e "${CYAN}     Copyright (C) 2026 Sigit-HDTEAMLabs           ${NC}"
        echo -e "${BLUE}==================================================${NC}"
        echo -e "${MAGENTA}─── A. USER & AKUN ──────────────────────────────${NC}"
        m " 1" "Generate User Cpanel"
        m " 2" "Update User Cpanel"
        m " 3" "Manajemen Akun"
        m " 4" "Backup / Restore"
        m " 5" "Run AutoSSL"
        echo -e "${MAGENTA}─── B. SECURITY ─────────────────────────────────${NC}"
        m " 6" "Disable PHP Functions (RCE + PHP2Shell)"
        m " 7" "CSF Firewall"
        m " 8" "cPHulkd"
        m " 9" "Scanning Virus ClamAV"
        echo -e "${MAGENTA}─── C. MONITORING ───────────────────────────────${NC}"
        m "10" "Cek Resource"
        m "11" "${BOLD}Searching X (PHP Scan ⚡ FAST)${NC}"
        m "12" "List crontab user"
        m "13" "Dump crontab user"
        echo -e "${MAGENTA}─── D. MAINTENANCE ──────────────────────────────${NC}"
        m "14" "Fix permission /home/user"
        m "15" "Clean Log Server"
        m "16" "Makecache, Update, Upgrade"
        m "17" "Stop/Start/Restart Service"
        echo -e "${MAGENTA}─── E. TUNING ───────────────────────────────────${NC}"
        m "18" "MySQL repair, optimize, tuning"
        m "19" "Apache Tuning"
        echo -e "${MAGENTA}─── F. UTILITIES ────────────────────────────────${NC}"
        m "20" "Autofix WHM"
        m "21" "Ekstrak Domain & IP A Record"
        echo -e "${BLUE}==================================================${NC}"
        echo -e "${CYAN} ⚡ PHP scanner: pre-filter + parallel (${WS_PARALLEL_JOBS} core)${NC}"
        echo -e "${CYAN} 🎭 Hidden file + 🦠 Ransomware + 🛡️ Rootkit${NC}"
        echo -e "${BLUE}==================================================${NC}"
        m " 0" "Keluar"
        echo -e "${BLUE}==================================================${NC}"
        read -r -p "$(echo -e ${CYAN}"Pilih menu [0-21]: "${NC})" choice
        case $choice in
            1) generate_user_txt ;;
            2) update_user_txt ;;
            3) manage_accounts ;;
            4) backup_restore_user ;;
            5) run_autossl ;;
            6) disable_php_functions ;;
            7) manage_csf ;;
            8) manage_cphulk ;;
            9) menu_scan_virus ;;
            10) cek_resource ;;
            11) menu_searching_x ;;
            12) show_all_crontabs ;;
            13) dump_all_crontabs ;;
            14) fix_permission ;;
            15) menu_clean_log_server ;;
            16) makecache_update ;;
            17) manage_services ;;
            18) mysql_repair_optimize ;;
            19) apache_tuning ;;
            20) autofix_whm ;;
            21) extract_dns ;;
            0) echo -e "${GREEN}Keluar.${NC}"; exit 0 ;;
            *) echo -e "${RED}Pilihan salah!${NC}"; sleep 2 ;;
        esac
    done
}

# =============================================================================
# START
# =============================================================================

mkdir -p "$FINGERPRINT_DIR"
init_known_services
sync_user_list
main_menu
