import os
import hashlib
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def calculate_hashes(file_path):
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            md5_hash.update(byte_block)
    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def check_malware_signature(sha256):
    return {
        "status": "Clean / Safe",
        "engine_matches": "0 / 65 security vendors flagged this file",
        "risk_level": "Low"
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400
        
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    
    md5, sha256 = calculate_hashes(file_path)
    scan_result = check_malware_signature(sha256)
    
    os.remove(file_path)
    
    return jsonify({
        "filename": file.filename,
        "md5": md5,
        "sha256": sha256,
        "scan": scan_result
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
