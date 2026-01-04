import os
import subprocess
import logging
import shlex
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# --- KONFIGURASI KEAMANAN ---

# 1. Rate Limiting: 20 request per menit per IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per minute"],
    storage_uri="memory://"
)

# 2. Whitelist Target (HANYA target ini yang boleh discan)
#    Ganti URL ini dengan target simulasi Anda sendiri.
TARGETS = {
    "http://testphp.vulnweb.com/listproducts.php?cat=1": "http://testphp.vulnweb.com/listproducts.php?cat=1",
    "http://testphp.vulnweb.com/artists.php?artist=1": "http://testphp.vulnweb.com/artists.php?artist=1"
}

# 3. Blacklist Flags (Opsi berbahaya yang dilarang keras)
FORBIDDEN_FLAGS = [
    "--os-shell", "--os-pwn", "--os-smb", "--os-bof", "--priv-esc",
    "--reg-read", "--reg-add", "--reg-del",
    "--file-write", "--file-read", "--file-dest",
    "--sql-shell", "--eval", "--smart", "--wizard",
    "--dns-domain", "--eta"
]

# Konfigurasi Logging
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(level=logging.INFO)

def log_activity(message):
    """Mencatat aktivitas dengan IP pengakses"""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    logging.info(f"{ip} - {message}")

@app.route('/')
def index():
    """Render halaman frontend"""
    return render_template('index.html')

@app.route('/targets', methods=['GET'])
def get_targets():
    """API untuk mengambil daftar target ID (tanpa mengekspos URL asli secara gamblang di UI jika tidak perlu)"""
    return jsonify({"targets": list(TARGETS.keys())})

@app.route('/run_sqlmap', methods=['POST'])
@limiter.limit("5 per minute") # Rate limit lebih ketat untuk endpoint eksekusi
def run_sqlmap():
    data = request.get_json()
    
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    target_id = data.get('target_id')
    user_flags = data.get('flags', '')

    # --- VALIDASI INPUT ---

    # 1. Validasi Target ID
    if target_id not in TARGETS:
        log_activity(f"BLOCKED: Invalid target_id '{target_id}'")
        return jsonify({"status": "error", "message": "Target ID tidak valid atau tidak terdaftar dalam whitelist."}), 403

    real_target_url = TARGETS[target_id]

    # 2. Validasi Flags (Sanitasi & Blacklist)
    # Menggunakan shlex.split untuk memparsing string argumen seperti shell
    try:
        flag_list = shlex.split(user_flags)
    except ValueError:
        return jsonify({"status": "error", "message": "Format flags tidak valid (unbalanced quotes)."}), 400

    # Cek apakah ada flag terlarang
    for flag in flag_list:
        # Cek exact match atau substring (misal --file-write)
        if any(banned in flag.lower() for banned in FORBIDDEN_FLAGS):
            log_activity(f"BLOCKED: User mencoba flag berbahaya '{flag}'")
            return jsonify({
                "status": "error", 
                "message": f"Security Alert: Flag '{flag}' dilarang digunakan di environment edukasi ini."
            }), 403

    # --- KONSTRUKSI PERINTAH ---
    
    # Path ke executable sqlmap (sesuai Dockerfile nanti)
    # Jika run local tanpa docker, pastikan 'sqlmap' ada di PATH atau ganti path absolut
    sqlmap_cmd = ['sqlmap', '-u', real_target_url, '--batch', '--disable-coloring']
    
    # Tambahkan flags aman dari user
    sqlmap_cmd.extend(flag_list)

    log_activity(f"EXECUTING: Target={target_id} Flags={user_flags}")

    try:
        # --- EKSEKUSI SUBPROCESS ---
        # Timeout diset 60 detik sesuai spesifikasi
        result = subprocess.run(
            sqlmap_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        output = result.stdout
        if result.stderr:
            output += "\n[STDERR]\n" + result.stderr

        return jsonify({
            "status": "success",
            "output": output
        })

    except subprocess.TimeoutExpired:
        log_activity(f"TIMEOUT: Target={target_id}")
        return jsonify({
            "status": "error",
            "output": "Proses dihentikan paksa (Timeout 60 detik). Query terlalu berat untuk demo."
        }), 504
        
    except FileNotFoundError:
        return jsonify({
            "status": "error",
            "message": "SQLMap tidak terinstall di server."
        }), 500

    except Exception as e:
        log_activity(f"ERROR: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Internal Server Error"
        }), 500

if __name__ == '__main__':
    # Mode debug dimatikan untuk production/docker
    app.run(host='0.0.0.0', port=8080)
