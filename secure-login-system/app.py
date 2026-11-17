import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import pyotp
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "users.db"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                twofa_enabled INTEGER NOT NULL DEFAULT 0,
                twofa_secret TEXT,
                created_at TEXT NOT NULL
            )
        """)
        db.commit()

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("_csrf_token", "")
        submitted = request.form.get("_csrf_token", "")
        if not token or not submitted or not hmac.compare_digest(token, submitted):
            return "Invalid or expired form token. Refresh the page and try again.", 400

@app.context_processor
def inject_csrf():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["_csrf_token"]}

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def valid_email(email):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))

def valid_password(password):
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            flash("Username must be 3–20 characters (letters, numbers, underscore).", "danger")
        elif not valid_email(email):
            flash("Enter a valid email address.", "danger")
        elif not valid_password(password):
            flash("Password must be 8+ characters with uppercase, lowercase, number and symbol.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            try:
                get_db().execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password), datetime.utcnow().isoformat())
                )
                get_db().commit()
                flash("Account created successfully. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username or email already exists.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identity, identity.lower())
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["_csrf_token"] = secrets.token_urlsafe(32)
            if user["twofa_enabled"]:
                session["pending_2fa_user"] = user["id"]
                return redirect(url_for("verify_2fa"))
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html")

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_2fa_user")
    if not pending_id:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (pending_id,)).fetchone()
        if user and user["twofa_secret"] and pyotp.TOTP(user["twofa_secret"]).verify(code, valid_window=1):
            session.clear()
            session["_csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Two-factor verification successful.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid authentication code.", "danger")
    return render_template("verify_2fa.html")

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("dashboard.html", user=user)

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not check_password_hash(user["password_hash"], current):
            flash("Current password is incorrect.", "danger")
        elif not valid_password(new):
            flash("New password must be 8+ characters with uppercase, lowercase, number and symbol.", "danger")
        elif new != confirm:
            flash("New passwords do not match.", "danger")
        elif check_password_hash(user["password_hash"], new):
            flash("Choose a password different from your current password.", "danger")
        else:
            get_db().execute("UPDATE users SET password_hash = ? WHERE id = ?",
                             (generate_password_hash(new), session["user_id"]))
            get_db().commit()
            session.clear()
            flash("Password changed. Please log in again.", "success")
            return redirect(url_for("login"))
    return render_template("change_password.html")

@app.route("/2fa/enable", methods=["GET", "POST"])
@login_required
def enable_2fa():
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user["twofa_enabled"]:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        secret = session.get("setup_2fa_secret")
        code = request.form.get("code", "").strip()
        if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
            get_db().execute("UPDATE users SET twofa_enabled = 1, twofa_secret = ? WHERE id = ?",
                             (secret, session["user_id"]))
            get_db().commit()
            session.pop("setup_2fa_secret", None)
            flash("Two-factor authentication enabled.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid code. Try again.", "danger")
    if "setup_2fa_secret" not in session:
        session["setup_2fa_secret"] = pyotp.random_base32()
    secret = session["setup_2fa_secret"]
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="Secure Login System")
    return render_template("enable_2fa.html", secret=secret, uri=uri)

@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    password = request.form.get("password", "")
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if check_password_hash(user["password_hash"], password):
        get_db().execute("UPDATE users SET twofa_enabled = 0, twofa_secret = NULL WHERE id = ?",
                         (session["user_id"],))
        get_db().commit()
        flash("Two-factor authentication disabled.", "success")
    else:
        flash("Password incorrect. 2FA was not disabled.", "danger")
    return redirect(url_for("dashboard"))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
