changelog: bug and patching, tweak code

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



