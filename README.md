# Linux SSH Hardening & Anti Brute-Force

Panduan dan skrip otomatis pengamanan akses SSH Linux Server (Ubuntu & Debian) untuk meredam serangan brute-force dan menjaga beban CPU/RAM tetap rendah.

Dikembangkan berdasarkan implementasi nyata pengamanan server infrastruktur dan aplikasi e-government Pemkab Sinjai oleh Tim CSIRT Diskominfosan Sinjai.

---

## Status Pengujian

- **Sudah dicoba dan diterapkan pada Ubuntu Server** (Ubuntu 24.04 LTS, OpenSSH 9.6p1) dan **Debian Server** (Debian 11, OpenSSH 8.4p1).
- Skrip `harden_ssh.sh` dilengkapi mode `--dry-run` serta pengecekan kompatibilitas otomatis terhadap versi OpenSSH yang terpasang (OpenSSH 8.x hingga 10.x) dan perlindungan anti-lockout sebelum konfigurasi diterapkan.

---

## Latar Belakang & Bukti Data Nyata

Setiap server Linux dengan IP publik yang membuka port default 22 dan autentikasi password menjadi sasaran empuk ribuan bot scanner global setiap hari.

Berdasarkan audit log nyata pada server kami:
- **12.375+ upaya login ilegal** tercatat hanya dalam hitungan hari.
- **91,7% (11.351 kali)** secara membabi buta menargetkan akun `root`.
- **Dampak Sumber Daya:** Setiap percobaan login memaksa prosesor menjalankan enkripsi hashing PAM (`unix_chkpwd`), menyebabkan context switching tinggi dan lonjakan *load average* hingga **> 1.80**.

### Perbandingan Kinerja Server

| Parameter | Sebelum Hardening (Port 22 & Password Aktif) | Setelah Hardening (Ubuntu Server Produksi) |
| :--- | :--- | :--- |
| **Upaya Brute-Force** | 12.375+ percobaan tercatat | Ditutup langsung di fase *preauth disconnect* |
| **Target Akun `root`** | 11.351 kali dicoba | Ditolak seketika (`PermitRootLogin no`) |
| **Beban CPU** | Boros CPU untuk enkripsi verifikasi password bot | **Nol komputasi hashing password** |
| **Load Average** | Sering melonjak > 1.50 - 1.88 saat diserang | **Sangat dingin di 0.06 - 0.20** |

---

## Fitur Utama Skrip

1. **Pencegahan Terkunci (Anti-Lockout Protection):** Memeriksa bahwa akun admin non-root memiliki SSH public key yang valid di `~/.ssh/authorized_keys` sekaligus hak `sudo` sebelum menonaktifkan login root dan password.
2. **Prioritas Drop-In `00-ssh-hardening.conf`:** Menggunakan awalan `00-` di `/etc/ssh/sshd_config.d/` karena `sshd` mengambil nilai **pertama** yang ditemukan (mengatasi konfigurasi bawaan cloud image seperti `50-cloud-init.conf` yang sering menyetel `PasswordAuthentication yes`).
3. **Dukungan Khusus Debian (Debian 11 / Image Minimal):** Jika `/etc/ssh/sshd_config` belum memuat `Include /etc/ssh/sshd_config.d/*.conf` (umum pada Debian 11), skrip otomatis mencadangkan `/etc/ssh/sshd_config` lalu menyisipkan baris `Include` tersebut di baris teratas agar `00-ssh-hardening.conf` dibaca paling awal sebelum opsi bawaan lainnya.
4. **Penyesuaian Versi OpenSSH Otomatis:** Memfilter `KexAlgorithms` (termasuk post-quantum `mlkem768`/`sntrup761` bila didukung) dan melewatkan `PerSourceMaxStartups` pada OpenSSH < 8.5 (misalnya OpenSSH 8.4p1 di Debian 11) agar daemon `sshd` selalu lolos uji sintaks.
5. **Pencadangan Otomatis:** Membuat backup bertanggal (`/etc/ssh/backup_*`) dari `/etc/ssh/sshd_config` dan `sshd_config.d/` sebelum melakukan perubahan.
6. **Validasi Sintaks & Konfigurasi Efektif:** Menjalankan `sshd -t` sebelum reload, lalu memverifikasi `sshd -T` setelah reload agar aturan dipastikan benar-benar aktif.
7. **Dukungan Fail2ban Otomatis (Opsional):** Jika `fail2ban` sudah terpasang di sistem, skrip otomatis memasang jail anti brute-force tambahan dengan waktu blokir progresif. (Untuk server dengan `AuthenticationMethods publickey` penuh, `PerSourceMaxStartups 2` pada OpenSSH 8.5+ sudah memutus bot pada fase `[preauth]` tanpa membebani tabel firewall).

---

## Struktur Folder

```text
ssh-antibruteforce/
├── harden_ssh.sh                    # Skrip installer otomatis (+ --dry-run)
├── configs/
│   ├── 00-ssh-hardening.conf        # Konfigurasi SSH (/etc/ssh/sshd_config.d/)
│   └── sshd-fail2ban.local          # Konfigurasi jail Fail2ban
├── LICENSE                          # Lisensi MIT
└── README.md                        # Panduan instalasi dan dokumentasi
```

---

## Cara Penggunaan

### 1. Pasang SSH Public Key & Pastikan Hak Sudo Terlebih Dahulu
Pastikan akun admin non-root di server sudah memiliki hak `sudo` serta pasangan kunci SSH (disarankan Ed25519):
```bash
# Dari komputer lokal / laptop Anda:
ssh-keygen -t ed25519 -C "admin@domain-anda"
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@ip-server-anda
```

Pastikan Anda bisa masuk ke server tanpa diminta password dan bisa menjalankan `sudo`:
```bash
ssh user@ip-server-anda
sudo id
```

### 2. Kloning Repositori ke Server
```bash
git clone https://github.com/muhammadtakdir/ssh-antibruteforce.git
cd ssh-antibruteforce
```

### 3. Uji Konfigurasi (Dry-Run, Opsional)
```bash
bash harden_ssh.sh --dry-run
```

### 4. Jalankan Skrip Hardening
```bash
sudo bash harden_ssh.sh
```
*(Bila dijalankan dari shell root langsung, tentukan akun admin non-root secara eksplisit: `sudo ADMIN_USER=nama_admin bash harden_ssh.sh`)*

### 5. Pengujian (Penting!)
**JANGAN menutup jendela terminal Anda terlebih dahulu!**  
Buka jendela terminal baru di komputer lokal Anda, lalu coba masuk kembali:
```bash
ssh user@ip-server-anda
```
Verifikasi juga bahwa login password dan root sudah tertutup:
```bash
ssh -o PubkeyAuthentication=no user@ip-server-anda
```
Bila berhasil login langsung menggunakan SSH Key dan percobaan tanpa key ditolak (`Permission denied (publickey)`), konfigurasi telah aktif dengan sempurna.

---

## Pengecualian Akun Khusus & Tunneling (Opsional)

### A. Akun SFTP dengan Password (jika masih dibutuhkan)
Jika di server Anda terdapat akun transfer file SFTP yang masih membutuhkan autentikasi password, tambahkan blok berikut di bagian paling bawah `/etc/ssh/sshd_config.d/00-ssh-hardening.conf`:

```sshd
Match User nama_user_sftp
    PasswordAuthentication yes
    AuthenticationMethods password
    ForceCommand internal-sftp
```
*(Direktif `AuthenticationMethods password` wajib dicantumkan di dalam blok `Match` karena secara global skrip menyetel `AuthenticationMethods publickey`.)*

### B. Jika Membutuhkan SSH Tunnel / ProxyJump (`ssh -L` / `ssh -J`)
Konfigurasi default menyetel `AllowTcpForwarding no` untuk memperkecil permukaan serangan. Jika Anda menggunakan VS Code Remote-SSH, SSH Tunnel, atau ProxyJump melalui server tersebut, ubah menjadi `AllowTcpForwarding yes` (atau batasi per user dengan `Match User`).

Setelah mengubah konfigurasi, uji sintaks dan muat ulang layanan SSH:
```bash
sudo sshd -t && sudo systemctl reload ssh
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|authenticationmethods'
```

---

## Lisensi
Didistribusikan di bawah Lisensi [MIT](LICENSE). Bebas digunakan dan dibagikan untuk meningkatkan keamanan sistem pemerintahan dan publik.
