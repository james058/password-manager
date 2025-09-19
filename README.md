# Flask Password Manager

A simple password manager web app built with **Python (Flask)** and **SQLite**, with password encryption using **AES (PyCryptodome)**.  
The app also checks if a password has been **compromised in known breaches** using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) API (k-anonymity model).

---

## Features
- Add, view, and delete saved passwords.
- Passwords are **encrypted with AES** before storage.
- Uses a unique IV (initialization vector) per entry for added security.
- Integration with **HIBP API**:
  - Alerts you if a password is compromised.
  - Does **not send your full password** to the API.
- Simple web interface built with Flask and HTML templates.

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/james058/password-manager.git
cd password-manager
```
### 2. Create the virtual environment(recommended)
```bash
python -m venv venv
```
Activate it: Windows (CMD): venv\Scripts\activate, Linux/macOS: source venv/bin/activate
### 3. install dependencies
```bash
pip install -r requirements.txt
```
## Usage
Run the app:
```bash
python app.py
```
Open in browser: go to http://127.0.0.1:5000

