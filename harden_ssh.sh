#!/usr/bin/env bash
# ==============================================================================
# Script Otomatis Hardening SSH & Anti Brute-Force Linux Server
# Mendukung Ubuntu Server (20.04 / 22.04 / 24.04+) & Debian (11 / 12+)
# Pengembang: Tim CSIRT Diskominfosan Sinjai (Muhammad Takdir)
#
# Penggunaan:
#   sudo bash harden_ssh.sh             # pasang hardening
#   bash harden_ssh.sh --dry-run        # hanya tampilkan & validasi config
#                                       # (tidak mengubah sistem, tanpa root)
#   sudo ADMIN_USER=nama bash harden_ssh.sh
#                                       # tentukan akun admin secara eksplisit
# ==============================================================================
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_SRC="${BASE_DIR}/configs/00-ssh-hardening.conf"
FAIL2BAN_SRC="${BASE_DIR}/configs/sshd-fail2ban.local"
CONF_DEST_DIR="/etc/ssh/sshd_config.d"
CONF_DEST="${CONF_DEST_DIR}/00-ssh-hardening.conf"
LEGACY_DEST="${CONF_DEST_DIR}/99-ssh-hardening.conf"   # nama file versi lama
FAIL2BAN_DEST="/etc/fail2ban/jail.d/99-sshd-hardening.local"
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

die()  { echo "[-] Error: $*" >&2; exit 1; }
warn() { echo "[!] $*"; }
info() { echo "[*] $*"; }
ok()   { echo "[+] $*"; }

echo "=========================================================="
echo "    Setup Hardening SSH & Anti Brute-Force Linux Server    "
echo "=========================================================="

[[ -x "${SSHD_BIN}" ]] || die "sshd tidak ditemukan. Pasang openssh-server terlebih dahulu."
[[ -f "${CONF_SRC}" ]] || die "Berkas ${CONF_SRC} tidak ditemukan."

if [[ ${DRY_RUN} -eq 0 && "${EUID}" -ne 0 ]]; then
    die "Jalankan skrip ini sebagai root (contoh: sudo bash harden_ssh.sh)"
fi

OPENSSH_VER="$(ssh -V 2>&1 | head -n1)"
info "Versi terdeteksi: ${OPENSSH_VER}"

# ------------------------------------------------------------------------------
# Harness uji sintaks: config minimal + host key sementara, sehingga
# "sshd -t" bisa dijalankan tanpa menyentuh konfigurasi sistem.
# ------------------------------------------------------------------------------
ssh-keygen -q -t ed25519 -N '' -f "${WORK_DIR}/hostkey" >/dev/null
mkdir -p "${WORK_DIR}/d"
printf 'Include %s/d/*.conf\nHostKey %s/hostkey\nPidFile none\n' \
    "${WORK_DIR}" "${WORK_DIR}" > "${WORK_DIR}/main.conf"

sshd_supports() {   # $1 = "Opsi=nilai"
    "${SSHD_BIN}" -t -f "${WORK_DIR}/main.conf" -o "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
# 1. Bangun config sesuai kemampuan OpenSSH di server ini
# ------------------------------------------------------------------------------
# Dibangun di luar folder d/ dulu: harness probe harus tetap kosong agar
# opsi yang tidak didukung tidak menggagalkan seluruh pengujian.
GEN_CONF="${WORK_DIR}/00-ssh-hardening.conf"
cp "${CONF_SRC}" "${GEN_CONF}"

WANT_KEX="$(awk '/^KexAlgorithms /{print $2}' "${CONF_SRC}")"
SUPPORTED_KEX="$(ssh -Q kex 2>/dev/null || true)"
KEX_LIST=""
IFS=',' read -r -a KEX_ARR <<< "${WANT_KEX}"
for k in "${KEX_ARR[@]}"; do
    if grep -qxF "${k}" <<< "${SUPPORTED_KEX}" && sshd_supports "KexAlgorithms=${k}"; then
        KEX_LIST="${KEX_LIST:+${KEX_LIST},}${k}"
    fi
done
[[ -n "${KEX_LIST}" ]] || die "Tidak ada algoritma KexAlgorithms yang didukung sshd ini."
sed -i "s|^KexAlgorithms .*|KexAlgorithms ${KEX_LIST}|" "${GEN_CONF}"

if ! sshd_supports "PerSourceMaxStartups=2"; then
    warn "OpenSSH ini belum mendukung PerSourceMaxStartups (butuh >= 8.5); baris tersebut dilewati."
    sed -i '/^PerSourceMaxStartups /d' "${GEN_CONF}"
fi
if ! sshd_supports "KbdInteractiveAuthentication=no"; then
    sed -i 's/^KbdInteractiveAuthentication /ChallengeResponseAuthentication /' "${GEN_CONF}"
fi

cp "${GEN_CONF}" "${WORK_DIR}/d/"
"${SSHD_BIN}" -t -f "${WORK_DIR}/main.conf" || die "Config hasil generate gagal uji sintaks sshd."
ok "Config hasil generate lolos uji sintaks (sshd -t)."
info "KexAlgorithms: ${KEX_LIST}"

# ------------------------------------------------------------------------------
# 2. Pengecekan anti-lockout: harus ada akun admin non-root yang
#    (a) memiliki SSH public key valid, dan (b) memiliki hak sudo.
# ------------------------------------------------------------------------------
check_admin() {
    local u="$1" home keys
    getent passwd "${u}" >/dev/null || { echo "akun '${u}' tidak ada"; return 1; }
    home="$(getent passwd "${u}" | cut -d: -f6)"
    keys="${home}/.ssh/authorized_keys"
    if [[ ! -s "${keys}" ]] || ! ssh-keygen -lf "${keys}" >/dev/null 2>&1; then
        echo "${keys} kosong / tidak berisi public key valid"; return 1
    fi
    if ! id -nG "${u}" | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; then
        if ! { sudo -n -l -U "${u}" 2>/dev/null | grep -q '(ALL'; }; then
            echo "akun '${u}' tidak memiliki hak sudo"; return 1
        fi
    fi
    return 0
}

ADMIN_USER="${ADMIN_USER:-${SUDO_USER:-}}"
if [[ ${DRY_RUN} -eq 1 && -z "${ADMIN_USER}" && "${EUID}" -ne 0 ]]; then
    ADMIN_USER="$(id -un)"
fi
if [[ -z "${ADMIN_USER}" || "${ADMIN_USER}" == "root" ]]; then
    MSG="Akun admin non-root tidak terdeteksi (skrip dijalankan langsung sebagai root). PermitRootLogin no akan mengunci akses root via SSH. Jalankan lewat 'sudo' dari akun admin, atau set ADMIN_USER=<nama_akun>."
    if [[ ${DRY_RUN} -eq 1 ]]; then warn "${MSG}"; else die "${MSG}"; fi
elif REASON="$(check_admin "${ADMIN_USER}")"; then
    ok "Anti-lockout: akun '${ADMIN_USER}' memiliki SSH key valid dan hak sudo."
else
    MSG="PERINGATAN KRUSIAL: ${REASON}. Pasang public key (disarankan Ed25519) dan pastikan hak sudo sebelum menonaktifkan login password/root."
    if [[ ${DRY_RUN} -eq 1 ]]; then warn "${MSG}"; else die "${MSG}"; fi
fi

if [[ ${DRY_RUN} -eq 1 ]]; then
    echo "----------------------------------------------------------"
    echo "[DRY-RUN] Config yang akan dipasang ke ${CONF_DEST}:"
    echo "----------------------------------------------------------"
    grep -vE '^\s*(#|$)' "${GEN_CONF}"
    echo "----------------------------------------------------------"
    echo "[DRY-RUN] Tidak ada perubahan pada sistem."
    exit 0
fi

# ------------------------------------------------------------------------------
# 3. Backup konfigurasi lama (dilakukan sebelum modifikasi apa pun)
# ------------------------------------------------------------------------------
BACKUP_DIR="/etc/ssh/backup_$(date +%Y%m%d_%H%M%S)"
info "Membuat backup konfigurasi SSH ke ${BACKUP_DIR}..."
mkdir -p "${BACKUP_DIR}"
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.d "${BACKUP_DIR}/" 2>/dev/null || true

restore_backup() {
    warn "Mengembalikan konfigurasi dari ${BACKUP_DIR}..."
    rm -f "${CONF_DEST}"
    [[ -f "${BACKUP_DIR}/sshd_config" ]] && \
        cp -a "${BACKUP_DIR}/sshd_config" /etc/ssh/sshd_config
    [[ -f "${BACKUP_DIR}/sshd_config.d/99-ssh-hardening.conf" ]] && \
        cp -a "${BACKUP_DIR}/sshd_config.d/99-ssh-hardening.conf" "${LEGACY_DEST}"
    return 0
}

# ------------------------------------------------------------------------------
# 4. Pastikan /etc/ssh/sshd_config memuat drop-in sshd_config.d
#    (Pada Debian 11 / beberapa image minimal, baris Include belum ada secara default;
#     disisipkan di paling atas agar nilai di 00-ssh-hardening.conf menjadi nilai PERTAMA)
# ------------------------------------------------------------------------------
if ! grep -Eiq '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    info "Menambahkan 'Include /etc/ssh/sshd_config.d/*.conf' di baris teratas /etc/ssh/sshd_config (khusus Debian 11 / image tanpa Include)..."
    {
        printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n'
        cat /etc/ssh/sshd_config
    } > "${WORK_DIR}/sshd_config.new"
    install -m 644 -o root -g root "${WORK_DIR}/sshd_config.new" /etc/ssh/sshd_config
fi

# ------------------------------------------------------------------------------
# 5. Pasang config (dan pensiunkan nama file versi lama)
# ------------------------------------------------------------------------------
info "Memasang konfigurasi hardening SSH..."
mkdir -p "${CONF_DEST_DIR}"
install -m 644 -o root -g root "${GEN_CONF}" "${CONF_DEST}"
if [[ -f "${LEGACY_DEST}" ]]; then
    rm -f "${LEGACY_DEST}"
    info "File versi lama ${LEGACY_DEST} dipindahkan ke backup."
fi

info "Menguji validitas sintaks sshd..."
if ! "${SSHD_BIN}" -t; then
    restore_backup
    die "Sintaks konfigurasi sshd bermasalah. Konfigurasi lama sudah dikembalikan."
fi
ok "Sintaks konfigurasi valid."

# ------------------------------------------------------------------------------
# 6. Reload sshd (sesi SSH yang sedang aktif tidak terputus)
# ------------------------------------------------------------------------------
reload_sshd() {
    local svc
    for svc in ssh sshd; do
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            systemctl reload "${svc}"; return $?
        fi
    done
    warn "Service ssh/sshd tidak aktif; konfigurasi berlaku saat service berikutnya dijalankan."
    return 0
}
info "Memuat ulang service sshd..."
if ! reload_sshd; then
    restore_backup
    "${SSHD_BIN}" -t && reload_sshd || true
    die "Reload sshd gagal. Konfigurasi lama sudah dikembalikan."
fi

# ------------------------------------------------------------------------------
# 7. Fail2ban (opsional, hanya bila sudah terpasang)
# ------------------------------------------------------------------------------
if [[ -d "/etc/fail2ban/jail.d" ]]; then
    info "Fail2ban terdeteksi, memasang jail sshd tambahan..."
    install -m 644 -o root -g root "${FAIL2BAN_SRC}" "${FAIL2BAN_DEST}"
    if systemctl is-active --quiet fail2ban; then
        systemctl reload fail2ban && ok "Fail2ban berhasil di-reload." || warn "Reload fail2ban gagal, periksa: fail2ban-client -d"
    fi
fi

# ------------------------------------------------------------------------------
# 8. Verifikasi konfigurasi EFEKTIF (bukan sekadar isi file)
# ------------------------------------------------------------------------------
EFFECTIVE="$("${SSHD_BIN}" -T 2>/dev/null)"
FAIL=0
for kv in "permitrootlogin no" "passwordauthentication no" "authenticationmethods publickey"; do
    if grep -qx "${kv}" <<< "${EFFECTIVE}"; then
        ok "Efektif: ${kv}"
    else
        warn "TIDAK efektif: '${kv}' (nilai saat ini: $(grep "^${kv%% *} " <<< "${EFFECTIVE}"))"
        FAIL=1
    fi
done
if [[ ${FAIL} -ne 0 ]]; then
    warn "Ada drop-in/konfigurasi lain yang mendahului file ini. Periksa:"
    grep -RniE '^\s*(PermitRootLogin|PasswordAuthentication|AuthenticationMethods)' \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ || true
fi

echo "=========================================================="
echo "[OK] SSH Hardening Diterapkan"
echo "     - Login Root       : PermitRootLogin no"
echo "     - Login Password   : Dinonaktifkan (Key-Only Auth)"
echo "     - Max Percobaan    : 3 kali per koneksi"
echo "     - File Konfigurasi : ${CONF_DEST}"
echo "     - Backup Lama      : ${BACKUP_DIR}"
echo "=========================================================="
echo "[PENTING] Buka jendela terminal baru untuk menguji login SSH"
echo "          SEBELUM menutup sesi terminal saat ini!"
echo "          Rollback darurat: sudo rm ${CONF_DEST} && sudo systemctl reload ssh"
