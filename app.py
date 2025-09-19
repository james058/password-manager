from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os
import hashlib
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "replace_with_strong_secret")

# Master passphrase (derive encryption key) - keep this secret, use env var in real use
MASTER_PASSPHRASE = os.environ.get("MASTER_PASSPHRASE", "supersecret-passphrase")
# Derive a 32-byte AES key from passphrase using PBKDF2 (salt kept static here only for example)
KDF_SALT = b"fixed_salt_example"  # In production, use per-user salt + store it
KEY = PBKDF2(MASTER_PASSPHRASE, KDF_SALT, dkLen=32, count=200000)

DB_FILENAME = "passwords.db"

# Initialize database
def init_db():
    with sqlite3.connect(DB_FILENAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            iv TEXT NOT NULL,
            pwned_count INTEGER DEFAULT 0
        )''')
        conn.commit()

init_db()

# Encryption using AES-CBC with random IV per record
def encrypt_password(password):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(password.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode(), base64.b64encode(iv).decode()

def decrypt_password(encrypted_password_b64, iv_b64):
    encrypted = base64.b64decode(encrypted_password_b64)
    iv = base64.b64decode(iv_b64)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted.decode()

# Check password against HIBP Pwned Passwords k-anonymity API
def check_pwned(password):
    """
    Returns the number of times password has been seen in breaches (int).
    Uses HIBP Pwned Passwords API via k-anonymity (first 5 hex chars).
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "PasswordManagerExample/1.0"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code != 200:
            # API error - treat as unknown / not pwned
            return 0
        # Response body: lines of "HASH_SUFFIX:COUNT"
        lines = resp.text.splitlines()
        for line in lines:
            parts = line.split(':')
            if len(parts) != 2:
                continue
            returned_suffix, count_str = parts
            if returned_suffix.strip().upper() == suffix:
                try:
                    return int(count_str.strip())
                except:
                    return 0
        return 0
    except Exception as e:
        # network error / timeout -> fail safe: return 0 (or -1 to indicate unknown)
        return 0

@app.route("/")
def index():
    with sqlite3.connect(DB_FILENAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, site, username, password, iv, pwned_count FROM passwords")
        rows = cursor.fetchall()

    decrypted_passwords = []
    for id, site, username, password_enc, iv_b64, pwned_count in rows:
        try:
            pw = decrypt_password(password_enc, iv_b64)
        except Exception:
            pw = "[decryption error]"
        decrypted_passwords.append((id, site, username, pw, pwned_count))
    return render_template("index.html", passwords=decrypted_passwords)

@app.route("/add", methods=["POST"])
def add_password():
    site = request.form["site"]
    username = request.form["username"]
    password = request.form["password"]

    # Check pwned count (before storing)
    pwned_count = check_pwned(password)

    encrypted_password, iv_b64 = encrypt_password(password)

    with sqlite3.connect(DB_FILENAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO passwords (site, username, password, iv, pwned_count) VALUES (?, ?, ?, ?, ?)",
            (site, username, encrypted_password, iv_b64, pwned_count)
        )
        conn.commit()

    if pwned_count > 0:
        flash(f"Warning: This password has been seen in data breaches. Consider changing it.", "danger")
    else:
        flash("Password saved successfully!", "success")
    return redirect(url_for("index"))

@app.route("/delete/<int:id>")
def delete_password(id):
    with sqlite3.connect(DB_FILENAME) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE id=?", (id,))
        conn.commit()

    flash("Password deleted!", "danger")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
