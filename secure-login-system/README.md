# Secure Login System

A Flask-based authentication web application featuring secure password hashing, parameterized SQLite queries, server-side sessions, CSRF protection, password changes, and optional TOTP two-factor authentication.

## Features
- User registration and login with username or email
- Password hashing using Werkzeug's password-hashing utilities
- SQLite persistence with parameterized SQL queries
- Input validation and password-strength rules
- Session management and logout
- CSRF token validation on POST requests
- Change-password workflow
- Optional authenticator-app 2FA (TOTP)

## Requirements
- Python 3.10+
- pip

## Run locally (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

If PowerShell blocks activation, run the app using:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

The SQLite database `users.db` is created automatically on first run.

## 2FA
From the dashboard, choose Enable 2FA. Add the displayed secret manually to an authenticator app (such as Google Authenticator or Microsoft Authenticator), then enter the current six-digit code to confirm. Keep the secret private.

## Security notes
- This is an educational starter project, not a production-ready identity service.
- Set a strong persistent `SECRET_KEY` environment variable before deployment.
- Use HTTPS and set `COOKIE_SECURE=1` in production.
- Add rate limiting, email verification, secure password-reset delivery, audit logging, and deployment hardening before public use.
- Do not commit `users.db`, secrets, or real user data.
