whmcpanel.sh adalah skrip Bash administrasi server WHM/cPanel yang dikhususkan untuk root user (/root/user.txt, /scripts/*, /var/cpanel/*). Skrip ini menggabungkan manajemen akun, keamanan (webshell/rootkit/ransomware), monitoring, maintenance, tuning, dan utility dalam satu antarmuka menu interaktif berwarna.

---

🚀 Cara Penggunaan

1. Prasyarat

· Server WHM/cPanel (CentOS/AlmaLinux/RockyLinux dengan yum/dnf)
· Akses root (wajib — banyak path absolut ke /root/, /scripts/, /var/cpanel/)
· Koneksi internet (untuk unduh fingerprint DB & paket)
· Bash (skrip akan exec bash "$0" jika dijalankan dengan sh)

2. Instalasi & Menjalankan

```bash
# Upload file
scp whmcpanel.sh root@server:/root/

# Set executable
chmod +x /root/whmcpanel.sh

# Jalankan sebagai root
/root/whmcpanel.sh
# atau
bash /root/whmcpanel.sh
```

3. Alur Pertama Kali

Saat dijalankan, skrip otomatis:

1. Membuat direktori /root/fingerprints/
2. Menginisialisasi daftar service (KNOWN_SERVICES)
3. Menjalankan sync_user_list → membuat /root/user.txt
4. Menampilkan menu utama

4. Navigasi

· Pilih nomor 0–21 pada prompt Pilih menu [0-21]:
· Submenu umumnya punya opsi 0 untuk kembali
· Tekan Enter saat muncul prompt Tekan Enter... untuk lanjut

==================================================
        WHM/cPanel Management Script v9.0         
     Copyright (C) 2026 Sigit-HDTEAMLabs           
==================================================
─── A. USER & AKUN ──────────────────────────────
 1. Generate User Cpanel
 2. Update User Cpanel
 3. Manajemen Akun
 4. Backup / Restore
 5. Run AutoSSL
─── B. SECURITY ─────────────────────────────────
 6. Disable PHP Functions (RCE + PHP2Shell)
 7. CSF Firewall
 8. cPHulkd
 9. Scanning Virus ClamAV
─── C. MONITORING ───────────────────────────────
10. Cek Resource
11. Searching X (PHP Scan ⚡ FAST)
12. List crontab user
13. Dump crontab user
─── D. MAINTENANCE ──────────────────────────────
14. Fix permission /home/user
15. Clean Log Server
16. Makecache, Update, Upgrade
17. Stop/Start/Restart Service
─── E. TUNING ───────────────────────────────────
18. MySQL repair, optimize, tuning
19. Apache Tuning
─── F. UTILITIES ────────────────────────────────
20. Autofix WHM
21. Ekstrak Domain & IP A Record
==================================================
 ⚡ PHP scanner: pre-filter + parallel (8 core)
 🎭 Hidden file + 🦠 Ransomware + 🛡️ Rootkit
==================================================
 0. Keluar
==================================================
Pilih menu [0-21]:



