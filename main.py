import os
import hashlib
import time
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

KNOWN_VIRUS_SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Clean (Empty File)",
    "malware_sample_sig": "Trojan.Android.Agent.Gen",
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Tidak ada file yang diunggah'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nama file kosong'}), 400

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
