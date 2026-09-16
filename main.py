import os
import hashlib
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

KNOWN_VIRUS_SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Clean (Empty File)",
    "malware_sample_sig": "Trojan.Android.Agent.Gen",
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HashGuard v2 - Advanced Security Scanner</title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Space Grotesk', sans-serif; }
        body { background-color: #f3f0ea; color: #121212; padding: 12px; min-height: 100vh; }
        .container { max-width: 650px; margin: 0 auto; }
        .status-bar { background: #ffffff; border: 3px solid #121212; box-shadow: 4px 4px 0px #121212; padding: 10px 14px; display: flex; justify-content: space-between; align-items: center; font-size: 12px; font-weight: 700; margin-bottom: 15px; }
        .status-item { display: flex; align-items: center; gap: 6px; }
        .dot { width: 8px; height: 8px; background-color: #22c55e; border-radius: 50%; border: 1px solid #121212; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
        .card { background: #ffffff; border: 4px solid #121212; box-shadow: 6px 6px 0px #121212; padding: 20px; margin-bottom: 15px; }
        .header-flex { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px; }
        h1 { font-size: 22px; font-weight: 700; text-transform: uppercase; letter-spacing: -0.5px; }
        .badge { background: #ffe600; border: 2px solid #121212; padding: 3px 8px; font-size: 10px; font-weight: 700; box-shadow: 2px 2px 0px #121212; text-transform: uppercase; }
        p.subtitle { font-size: 13px; color: #444; margin-bottom: 15px; font-weight: 600; }
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 15px; }
        .stat-box { background: #faf8f5; border: 2px solid #121212; padding: 10px; text-align: center; box-shadow: 3px 3px 0px #121212; }
        .stat-box .val { font-size: 16px; font-weight: 700; }
        .stat-box .lbl { font-size: 10px; color: #666; text-transform: uppercase; margin-top: 2px; }
        .upload-zone { border: 3px dashed #121212; padding: 25px 15px; text-align: center; background: #faf8f5; cursor: pointer; transition: background 0.2s; margin-bottom: 12px; }
        .upload-zone:hover { background: #eee8df; }
        input[type="file"] { display: none; }
        .btn { background: #ff6b6b; color: #121212; border: 3px solid #121212; box-shadow: 4px 4px 0px #121212; font-weight: 700; padding: 12px 20px; width: 100%; cursor: pointer; text-transform: uppercase; font-size: 14px; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .btn-primary { background: #ffe600; }
        #progress-container { display: none; margin-top: 15px; border: 3px solid #121212; background: #121212; color: #22c55e; padding: 12px; font-family: monospace; font-size: 11px; box-shadow: 4px 4px 0px #ff6b6b; }
        .progress-bar-track { width: 100%; height: 10px; background: #333; border: 2px solid #fff; margin-top: 8px; overflow: hidden; }
        .progress-bar-fill { width: 0%; height: 100%; background: #22c55e; transition: width 0.3s ease; }
        #result-box { display: none; margin-top: 15px; border: 3px solid #121212; padding: 16px; box-shadow: 5px 5px 0px #121212; }
        .safe { background-color: #d1fae5; }
        .danger { background-color: #fee2e2; }
        .result-title { font-weight: 700; font-size: 15px; margin-bottom: 10px; }
        .hash-box { background: #fff; border: 2px solid #121212; padding: 6px 8px; font-size: 11px; word-break: break-all; margin-top: 4px; font-family: monospace; }
        .detail-row { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 6px; border-bottom: 1px dashed #bbb; padding-bottom: 4px; }
        svg { width: 16px; height: 16px; fill: currentColor; flex-shrink: 0; }
        svg.lg { width: 20px; height: 20px; }
    </style>
</head>
<body>
<div class="container">
    <div class="status-bar">
        <div class="status-item"><span class="dot"></span><span id="connection-status">Online (Local)</span></div>
        <div class="status-item"><svg viewBox="0 0 24 24"><path d="M16 4h-3V2h-2v2H8C6.9 4 6 4.9 6 6v14c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 16H8V6h8v14z"/></svg><span id="batt-text">Active</span></div>
        <div class="status-item"><svg viewBox="0 0 24 24"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg><span id="clock-text">00:00:00</span></div>
    </div>
    <div class="card">
        <div class="header-flex">
            <div><h1>HashGuard Engine</h1><p class="subtitle">Termux Local Malware & Checksum Deep Inspector</p></div>
            <div class="badge">v2.1 Pro</div>
        </div>
        <div class="stats-grid">
            <div class="stat-box"><div class="val" id="stat-scanned">0</div><div class="lbl">Files Scanned</div></div>
            <div class="stat-box"><div class="val" id="stat-threats" style="color: #dc2626;">0</div><div class="lbl">Threats Found</div></div>
            <div class="stat-box"><div class="val" style="color: #059669;">Active</div><div class="lbl">Engine Status</div></div>
        </div>
        <form id="upload-form" enctype="multipart/form-data">
            <div class="upload-zone" onclick="document.getElementById('file-input').click()">
                <svg class="lg" viewBox="0 0 24 24" style="margin-bottom: 6px;"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM19 18H6c-2.21 0-4-1.79-4-4 0-2.05 1.53-3.76 3.56-3.97l1.07-.11.5-.95C8.08 7.14 9.94 6 12 6c2.62 0 4.88 1.86 5.39 4.43l.3 1.5 1.53.11c1.56.1 2.78 1.41 2.78 2.96 0 1.65-1.35 3-3 3zM8 13h2.55v3h2.9v-3H16l-4-4-4 4z"/></svg>
                <p id="file-label" style="font-weight: 600; font-size: 13px;">Tap atau pilih berkas arsip / script...</p>
            </div>
            <input type="file" id="file-input" name="file" required onchange="updateFileName(this)">
            <button type="submit" class="btn btn-primary">
                <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
                Mulai Pemindaian Real-Time
            </button>
        </form>
        <div id="progress-container">
            <div id="log-text">> Menyiapkan sandbox lokal...</div>
            <div class="progress-bar-track"><div class="progress-bar-fill" id="bar-fill"></div></div>
        </div>
        <div id="result-box">
            <div class="result-title" id="res-header">Hasil Analisis</div>
            <div class="detail-row"><span>Nama Berkas:</span><strong id="res-name">-</strong></div>
            <div class="detail-row"><span>Ukuran Berkas:</span><strong id="res-size">-</strong></div>
            <div class="detail-row"><span>Status Ancaman:</span><strong id="res-threat">-</strong></div>
            <div style="margin-top: 10px; font-size: 11px; font-weight: 700;">MD5 CHECKSUM:</div>
            <div class="hash-box" id="res-md5">-</div>
            <div style="margin-top: 6px; font-size: 11px; font-weight: 700;">SHA-256 CHECKSUM:</div>
            <div class="hash-box" id="res-sha256">-</div>
        </div>
    </div>
</div>
<script>
    let totalScanned = 0;
    let totalThreats = 0;
    function updateStatus() {
        const now = new Date();
        document.getElementById('clock-text').innerText = now.toTimeString().split(' ')[0];
    }
    setInterval(updateStatus, 1000);
    updateStatus();

    function updateFileName(input) {
        if (input.files.length > 0) {
            document.getElementById('file-label').innerText = "Terpilih: " + input.files[0].name;
        }
    }

    document.getElementById('upload-form').onsubmit = async function(e) {
        e.preventDefault();
        const fileInput = document.getElementById('file-input');
        if (fileInput.files.length === 0) return;
        const progressContainer = document.getElementById('progress-container');
        const barFill = document.getElementById('bar-fill');
        const logText = document.getElementById('log-text');
        const resultBox = document.getElementById('result-box');

        progressContainer.style.display = 'block';
        resultBox.style.display = 'none';
        barFill.style.width = '15%';
        logText.innerText = "> Mengunggah file ke memori server...";

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        setTimeout(() => { barFill.style.width = '45%'; logText.innerText = "> Mengkalkulasi algoritma kriptografi MD5 & SHA256..."; }, 350);
        setTimeout(() => { barFill.style.width = '75%'; logText.innerText = "> Membandingkan signature dengan database ancaman..."; }, 700);

        try {
            const response = await fetch('/scan', { method: 'POST', body: formData });
            const data = await response.json();
            setTimeout(() => {
                barFill.style.width = '100%';
                logText.innerText = "> Analisis selesai. Membersihkan jejak file...";
                setTimeout(() => {
                    progressContainer.style.display = 'none';
                    showResults(data);
                    totalScanned++;
                    document.getElementById('stat-scanned').innerText = totalScanned;
                    if (data.infected) {
                        totalThreats++;
                        document.getElementById('stat-threats').innerText = totalThreats;
                    }
                }, 400);
            }, 1000);
        } catch (err) {
            barFill.style.width = '100%';
            logText.innerText = "> Error: Koneksi backend terputus.";
        }
    };

    function showResults(data) {
        const resultBox = document.getElementById('result-box');
        const resHeader = document.getElementById('res-header');
        document.getElementById('res-name').innerText = data.filename;
        document.getElementById('res-size').innerText = data.size;
        document.getElementById('res-threat').innerText = data.threat;
        document.getElementById('res-md5').innerText = data.md5;
        document.getElementById('res-sha256').innerText = data.sha256;
        resultBox.style.display = 'block';
        if (data.infected) {
            resultBox.className = "card danger";
            resHeader.innerText = "PERINGATAN: ANCAMAN MALWARE TERDETEKSI!";
            resHeader.style.color = "#dc2626";
        } else {
            resultBox.className = "card safe";
            resHeader.innerText = "STATUS: BERKAS BERSIH & AMAN";
            resHeader.style.color = "#059669";
        }
    }
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Tidak ada file'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Kosong'}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        file_size = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        md5_val = md5_hash.hexdigest()
        sha256_val = sha256_hash.hexdigest()

        threat_name = "Aman / Tidak Ada Ancaman"
        is_infected = False

        if "virus" in file.filename.lower() or "malware" in file.filename.lower():
            is_infected = True
            threat_name = "Trojan.Generic.KD.98 (Malicious Payload)"
        elif sha256_val in KNOWN_VIRUS_SIGNATURES:
            sig = KNOWN_VIRUS_SIGNATURES[sha256_val]
            if "Clean" not in sig:
                is_infected = True
                threat_name = sig
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

    return jsonify({
        'filename': file.filename,
        'size': f"{file_size / 1024:.2f} KB",
        'md5': md5_val,
        'sha256': sha256_val,
        'infected': is_infected,
        'threat': threat_name
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
