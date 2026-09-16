# HashGuard v2

**HashGuard** adalah utilitas keamanan web lokal yang berjalan di **Termux** untuk memindai integritas berkas (MD5/SHA-256) dan mendeteksi malware secara instan, aman, dan real-time langsung dari HP...

Credit : HJK - Gijutsu

## Fitur Utama [UPDATE]

- **Status Bar Real-Time**: Memantau status koneksi internet, indikator baterai perangkat, dan jam digital secara langsung di dalam web dashboard.
- **Kalkulasi Checksum**: Menghitung hash kriptografi **MD5** dan **SHA-256** secara instan untuk verifikasi integritas file.
- **Animasi Proses & Terminal Log**: Dilengkapi progress bar dinamis dan log terminal bergaya hacker saat pemindaian berkas berlangsung.
- **Deteksi Spesifik Ancaman**: Mampu mengenali dan melaporkan jenis malware atau virus spesifik jika berkas terindikasi berbahaya.
- **Auto-Cleanup (Privasi Terjaga)**: Secara otomatis menghapus berkas yang diunggah dari direktori server begitu proses pemindaian selesai.

---

## Cara Instalasi di Termux

Jalankan perintah dibawah ini

```bash
# Clone repository
git clone [https://github.com/HJK103/Hashguard.git](https://github.com/HJK103/Hashguard.git)
cd Hashguard

# Masuk ke folder proyek dan pastikan struktur direktori (templates/index.html) sudah sesuai

# Install dependensi Flask & Requests
pip install flask requests

# Jalankan server utama
python main.py

Jika tidak work, saya sarankan untuk mendownload seluruh file/folder terlebih dahulu
lalu ketik cd /storage/emulated/0/githubtools/virusdetector
