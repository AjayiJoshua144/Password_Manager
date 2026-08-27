from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from functools import wraps
import secrets
import string

import database as db
import crypto

# ── APP SETUP ────────────────────────────────────────────────
app = Flask(__name__)

# Secret key signs the session cookie (change this in production!)
app.secret_key = secrets.token_hex(32)

# Session cookie security settings
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS can't read the cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection


# ── LOGIN REQUIRED DECORATOR ─────────────────────────────────
def login_required(f):
    """
    A decorator that blocks access to a route if the user isn't logged in.
    Used like: @login_required above any route that needs auth.

    Decorators in Python are wrappers around functions — they run extra
    code before/after the actual route function.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── ROUTES ───────────────────────────────────────────────────

@app.route("/")
def index():
    """Landing page — redirect to vault if already logged in."""
    if "user_id" in session:
        return redirect(url_for("vault"))
    return render_template("index.html")


# ── REGISTRATION ─────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    GET  → Show registration form.
    POST → Validate input, hash master password, store user in DB.
    """
    if request.method == "GET":
        return render_template("register.html")

    # Read form fields
    username        = request.form.get("username", "").strip()
    master_password = request.form.get("master_password", "")
    confirm_pw      = request.form.get("confirm_password", "")

    # ── Basic validation ──────────────────────────────────────
    if not username or not master_password:
        flash("Username and master password are required.", "error")
        return render_template("register.html")

    if master_password != confirm_pw:
        flash("Passwords do not match.", "error")
        return render_template("register.html")

    if len(master_password) < 8:
        flash("Master password must be at least 8 characters.", "error")
        return render_template("register.html")

    # ── Generate PBKDF2 salt for this user ───────────────────
    # This salt is used to derive the encryption key on every login.
    kdf_salt = crypto.generate_salt()

    # ── Store user in DB ─────────────────────────────────────
    success = db.register_user(username, master_password, kdf_salt)

    if not success:
        flash("Username already taken. Try another.", "error")
        return render_template("register.html")

    flash("Account created! Please log in.", "success")
    return redirect(url_for("login"))


# ── LOGIN ─────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET  → Show login form.
    POST → Verify master password. If correct, derive the encryption key
           and store it in the session for use during this session.

    ⚠️  Student Note:
    We store the DERIVED KEY (not the master password) in the session.
    The key is needed to encrypt/decrypt vault entries.
    The master password itself is NEVER stored anywhere.
    """
    if request.method == "GET":
        return render_template("login.html")

    username        = request.form.get("username", "").strip()
    master_password = request.form.get("master_password", "")

    # ── Fetch user from DB ───────────────────────────────────
    user = db.get_user(username)

    if not user:
        flash("Invalid username or password.", "error")   # Generic message (security)
        return render_template("login.html")

    # ── Verify bcrypt password hash ──────────────────────────
    if not db.verify_password(master_password, user["password_hash"]):
        flash("Invalid username or password.", "error")
        return render_template("login.html")

    # ── Derive the encryption key ────────────────────────────
    # Retrieve the stored PBKDF2 salt (hex → bytes)
    kdf_salt = bytes.fromhex(user["kdf_salt"])

    # Run PBKDF2 to get the 256-bit encryption key
    enc_key = crypto.derive_key(master_password, kdf_salt)

    # ── Store session data ───────────────────────────────────
    session["user_id"]  = user["id"]
    session["username"] = user["username"]
    # Store key as hex string (session stores strings, not raw bytes)
    session["enc_key"]  = enc_key.hex()

    flash(f"Welcome back, {username}!", "success")
    return redirect(url_for("vault"))


# ── VAULT (Main Dashboard) ────────────────────────────────────
@app.route("/vault")
@login_required
def vault():
    """
    Shows all stored (still encrypted) vault entries.
    Passwords are NOT decrypted here — only when the user clicks 'Reveal'.
    This limits how long the plain text is in memory.
    """
    user_id = session["user_id"]
    entries = db.get_vault_entries(user_id)
    count   = db.count_vault_entries(user_id)
    return render_template("vault.html",
                           entries=entries,
                           count=count,
                           username=session["username"])


# ── ADD VAULT ENTRY ───────────────────────────────────────────
@app.route("/vault/add", methods=["POST"])
@login_required
def add_entry():
    """
    Encrypts the plain-text password using the session key,
    then stores the encrypted blob in the DB.
    """
    site_name      = request.form.get("site_name", "").strip()
    site_url       = request.form.get("site_url", "").strip()
    username_entry = request.form.get("username_entry", "").strip()
    plain_password = request.form.get("password", "")
    notes          = request.form.get("notes", "").strip()

    if not site_name or not username_entry or not plain_password:
        flash("Site name, username, and password are required.", "error")
        return redirect(url_for("vault"))

    # Retrieve the encryption key from session
    enc_key = bytes.fromhex(session["enc_key"])

    # Encrypt the password before storing
    encrypted = crypto.encrypt(plain_password, enc_key)

    # Encrypt notes too if provided (good practice)
    enc_notes = crypto.encrypt(notes, enc_key) if notes else ""

    db.add_vault_entry(
        session["user_id"], site_name, site_url,
        username_entry, encrypted, enc_notes
    )

    # Clear the plain password variable (best-effort in Python)
    plain_password = ""

    flash(f"'{site_name}' saved to vault.", "success")
    return redirect(url_for("vault"))


# ── REVEAL PASSWORD (AJAX) ────────────────────────────────────
@app.route("/vault/reveal/<int:entry_id>", methods=["POST"])
@login_required
def reveal_password(entry_id):
    """
    Called via JavaScript fetch() when user clicks 'Show Password'.
    Decrypts and returns the password as JSON.
    Never renders it in a full page — reduces exposure.
    """
    entry = db.get_vault_entry(entry_id, session["user_id"])

    if not entry:
        return jsonify({"error": "Entry not found."}), 404

    try:
        enc_key  = bytes.fromhex(session["enc_key"])
        plain_pw = crypto.decrypt(entry["enc_password"], enc_key)
        return jsonify({"password": plain_pw})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ── EDIT VAULT ENTRY ──────────────────────────────────────────
@app.route("/vault/edit/<int:entry_id>", methods=["POST"])
@login_required
def edit_entry(entry_id):
    """Updates a vault entry. Re-encrypts the new password."""
    entry = db.get_vault_entry(entry_id, session["user_id"])
    if not entry:
        flash("Entry not found.", "error")
        return redirect(url_for("vault"))

    site_name      = request.form.get("site_name", "").strip()
    site_url       = request.form.get("site_url", "").strip()
    username_entry = request.form.get("username_entry", "").strip()
    plain_password = request.form.get("password", "")
    notes          = request.form.get("notes", "").strip()

    enc_key   = bytes.fromhex(session["enc_key"])
    encrypted = crypto.encrypt(plain_password, enc_key)
    enc_notes = crypto.encrypt(notes, enc_key) if notes else ""

    db.update_vault_entry(entry_id, session["user_id"],
                          site_name, site_url, username_entry,
                          encrypted, enc_notes)
    plain_password = ""
    flash(f"'{site_name}' updated.", "success")
    return redirect(url_for("vault"))


# ── DELETE VAULT ENTRY ────────────────────────────────────────
@app.route("/vault/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete_entry(entry_id):
    """Permanently removes a vault entry."""
    db.delete_vault_entry(entry_id, session["user_id"])
    flash("Entry deleted.", "success")
    return redirect(url_for("vault"))


# ── PASSWORD GENERATOR (AJAX) ─────────────────────────────────
@app.route("/generate")
@login_required
def generate_password():
    """
    Generates a cryptographically secure random password.
    Uses Python's secrets module (NOT random — that's predictable).

    Returns JSON: {"password": "..."}
    Called from vault.js via fetch().
    """
    length = int(request.args.get("length", 16))
    length = max(8, min(length, 64))   # Clamp between 8 and 64

    # Character pools
    chars = (
        string.ascii_uppercase +
        string.ascii_lowercase +
        string.digits +
        "!@#$%^&*()-_=+[]"
    )

    # secrets.choice() uses the OS random number generator (cryptographic)
    password = "".join(secrets.choice(chars) for _ in range(length))

    return jsonify({"password": password})


# ── LOGOUT ────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    """
    Clears the entire session — removes user_id, username, AND enc_key.
    The encryption key is gone from memory when the session is cleared.
    """
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ── RUN ───────────────────────────────────────────────────────
if __name__ == "__main__":
    db.init_db()          # Create tables if not present
    print("\n SecureVault Password Manager")
    print("   Running at: http://127.0.0.1:5000\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
