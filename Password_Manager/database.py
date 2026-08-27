# =============================================================
#  database.py  —  SQLite Database Layer
#  Author : Ajayi Joshua Abayomi | Babcock University | 300L
#
#  Two tables:
#    users  → stores registered users (hashed master passwords)
#    vault  → stores encrypted password entries for each user
#
#  We use bcrypt to hash the master password for LOGIN checks.
#  We use PBKDF2 (in crypto.py) to DERIVE the encryption key.
#  These are two SEPARATE operations — as a student, one mistake
#  we make is that we think one hash serves both purposes. It doesn't.
# =============================================================

import sqlite3
import bcrypt
from datetime import datetime

DB_PATH = "passmanager.db"


# ── CONNECT TO DATABASE ───────────────────────────────────────
def get_connection():
    """Opens (or creates) the SQLite database file."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # Rows behave like dicts
    return conn


# ── CREATE TABLES (run once on startup) ──────────────────────
def init_db():
    """
    Creates the 'users' and 'vault' tables if they don't exist.
    SQLite creates the .db file automatically on first run.
    """
    conn = get_connection()
    cur  = conn.cursor()

    # ── Users table ──────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,  -- bcrypt hash of master password
            kdf_salt      TEXT    NOT NULL,  -- hex-encoded PBKDF2 salt
            created_at    TEXT    NOT NULL
        )
    """)

    # ── Vault table ──────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER NOT NULL,
            site_name      TEXT    NOT NULL,   -- e.g. "Gmail"
            site_url       TEXT,               -- e.g. "https://gmail.com"
            username_entry TEXT    NOT NULL,   -- login username/email for that site
            enc_password   TEXT    NOT NULL,   -- AES-GCM encrypted password (base64)
            notes          TEXT,               -- optional notes (also encrypted)
            created_at     TEXT    NOT NULL,
            updated_at     TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Tables ready.")


# ── USER FUNCTIONS ────────────────────────────────────────────

def register_user(username: str, master_password: str, kdf_salt: bytes) -> bool:
    """
    Registers a new user.

    Steps:
      1. Hash the master password with bcrypt (for future login checks).
      2. Store username, bcrypt hash, and the PBKDF2 salt in the DB.

    Why store the kdf_salt?
      → We need it every time the user logs in to re-derive the encryption key.
      → The salt is NOT secret — it just makes each user's key unique.

    Returns True on success, False if username already taken.
    """
    # Bcrypt automatically generates its own internal salt
    pw_bytes   = master_password.encode("utf-8")
    pw_hash    = bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=12))

    # Store PBKDF2 salt as hex string
    salt_hex   = kdf_salt.hex()
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_connection()
        conn.execute(
            "INSERT INTO users (username, password_hash, kdf_salt, created_at) VALUES (?,?,?,?)",
            (username, pw_hash.decode("utf-8"), salt_hex, created_at)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        # UNIQUE constraint on username failed — username taken
        return False


def get_user(username: str):
    """
    Fetches a user row by username.
    Returns a dict-like Row object or None.
    """
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return user


def verify_password(master_password: str, stored_hash: str) -> bool:
    """
    Checks if the entered master password matches the stored bcrypt hash.
    bcrypt.checkpw() does the work — we never store or compare plain text.
    """
    return bcrypt.checkpw(
        master_password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )


# ── VAULT FUNCTIONS ───────────────────────────────────────────

def add_vault_entry(user_id: int, site_name: str, site_url: str,
                    username_entry: str, enc_password: str, notes: str = "") -> int:
    """
    Inserts a new encrypted vault entry.
    Returns the new entry's ID.
    """
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    cur  = conn.execute(
        """INSERT INTO vault
           (user_id, site_name, site_url, username_entry, enc_password, notes, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (user_id, site_name, site_url, username_entry, enc_password, notes, now, now)
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return new_id


def get_vault_entries(user_id: int):
    """Returns all vault entries for a user (still encrypted)."""
    conn     = get_connection()
    entries  = conn.execute(
        "SELECT * FROM vault WHERE user_id = ? ORDER BY site_name ASC",
        (user_id,)
    ).fetchall()
    conn.close()
    return entries


def get_vault_entry(entry_id: int, user_id: int):
    """Fetches a single vault entry (verifies it belongs to this user)."""
    conn  = get_connection()
    entry = conn.execute(
        "SELECT * FROM vault WHERE id = ? AND user_id = ?",
        (entry_id, user_id)
    ).fetchone()
    conn.close()
    return entry


def update_vault_entry(entry_id: int, user_id: int, site_name: str,
                       site_url: str, username_entry: str,
                       enc_password: str, notes: str):
    """Updates an existing vault entry."""
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    conn.execute(
        """UPDATE vault SET
           site_name=?, site_url=?, username_entry=?,
           enc_password=?, notes=?, updated_at=?
           WHERE id=? AND user_id=?""",
        (site_name, site_url, username_entry, enc_password, notes, now, entry_id, user_id)
    )
    conn.commit()
    conn.close()


def delete_vault_entry(entry_id: int, user_id: int):
    """Permanently deletes a vault entry."""
    conn = get_connection()
    conn.execute(
        "DELETE FROM vault WHERE id = ? AND user_id = ?",
        (entry_id, user_id)
    )
    conn.commit()
    conn.close()


def count_vault_entries(user_id: int) -> int:
    """Returns total number of stored passwords for a user."""
    conn  = get_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM vault WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    conn.close()
    return count
