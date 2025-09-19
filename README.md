A simple password manager web app built with Python (Flask) and SQLite, with password encryption using AES (PyCryptodome).  
The app also checks if a password has been compromised in known breaches using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) API (k-anonymity model).

## Project structure
password-manager/
│── app.py # Main Flask application
│── requirements.txt # Project dependencies
│── templates/
│ └── index.html # Frontend UI
│── static/ # (optional) CSS/JS files
│── .gitignore # Files to ignore in Git
