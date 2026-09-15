# HashGuard

A lightweight, local web-based file integrity and malware scanner designed specifically for Termux, featuring a high-contrast Dark Neo-Brutalist interface.

## Features
* **Hash Calculation:** Instantly computes cryptographic `MD5` and `SHA-256` hashes for any uploaded file to verify data integrity.
* **Threat Detection:** Scans files against digital threat signatures to identify potential malware or trojans.
* **Auto-Cleanup:** Automatically deletes uploaded files from the local server directory immediately after the scan completes to protect your storage and privacy.
* **Local Web Dashboard:** Runs entirely on `localhost` via Python Flask, accessible directly through your mobile browser with a bold, high-contrast UI.

## Installation & Usage

1. how to install/use?

2. Install the required dependencies: pip install flask requests

3. Run the application server: python app.py

4. Open your mobile browser and access the local dashboard:

[THE FULL TUTORIAL FOR NEWBIE]

pkg update && pkg install python git -y

git clone https://github.com/HJK103/Hashguard.git

cd Hashguard

pip install flask requests

python app.py
