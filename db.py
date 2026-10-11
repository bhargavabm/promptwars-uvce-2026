"""SQLite persistence layer for Bankism accounts, bank details, and codes.

The database file location is taken from the ``BANKISM_DB`` environment
variable so that tests can point at a temporary file, falling back to
``bankism.db`` next to this module for normal use.
"""

import hashlib
import os
import sqlite3
import time
from datetime import datetime, timezone

# Default time-to-live for a demonstration verification code, in seconds.
CODE_TTL_SECONDS = 300

# Schema created on first use. ``accepted_privacy_at`` is also added to older
# databases by ``_migrate`` when the column is missing.
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_method TEXT NOT NULL,
    google_sub TEXT UNIQUE,
    phone TEXT UNIQUE,
    name TEXT,
    email TEXT,
    created_at TEXT NOT NULL,
    accepted_privacy_at TEXT
);

CREATE TABLE IF NOT EXISTS bank_details (
    user_id INTEGER PRIMARY KEY,
    account_holder TEXT,
    bank_name TEXT,
    ifsc TEXT,
    account_last4 TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_codes (
    phone TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);
"""


def get_db_path():
    """Return the SQLite database path, honouring the BANKISM_DB variable."""
    configured = os.getenv("BANKISM_DB")
    if configured:
        return configured
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "bankism.db")


def _now_iso():
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _migrate(conn):
    """Add missing columns to an existing users table (schema migration step)."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "accepted_privacy_at" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN accepted_privacy_at TEXT")
        conn.commit()


def connect():
    """Open a connection with the schema ensured and migrations applied."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def init_db():
    """Create the database file and schema if they do not exist yet."""
    conn = connect()
    conn.commit()
    conn.close()


def hash_code(code):
    """Return the hex SHA-256 digest of a verification code."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _row_to_dict(row):
    """Convert a sqlite3.Row to a plain dictionary, or None."""
    return dict(row) if row is not None else None


def find_or_create_google_user(google_sub, name, email, accepted_privacy_at=None):
    """Return the user for a Google subject, creating the account on first use."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE google_sub = ?", (google_sub,)
        ).fetchone()
        if row is None:
            cursor = conn.execute(
                "INSERT INTO users "
                "(auth_method, google_sub, name, email, created_at, accepted_privacy_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("google", google_sub, name, email, _now_iso(), accepted_privacy_at),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
        elif accepted_privacy_at and not row["accepted_privacy_at"]:
            conn.execute(
                "UPDATE users SET accepted_privacy_at = ? WHERE id = ?",
                (accepted_privacy_at, row["id"]),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (row["id"],)
            ).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def find_or_create_phone_user(phone, accepted_privacy_at=None):
    """Return the user for a phone number, creating the account on first use."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE phone = ?", (phone,)
        ).fetchone()
        if row is None:
            cursor = conn.execute(
                "INSERT INTO users "
                "(auth_method, phone, name, email, created_at, accepted_privacy_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("phone", phone, phone, None, _now_iso(), accepted_privacy_at),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
        elif accepted_privacy_at and not row["accepted_privacy_at"]:
            conn.execute(
                "UPDATE users SET accepted_privacy_at = ? WHERE id = ?",
                (accepted_privacy_at, row["id"]),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (row["id"],)
            ).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def get_user(user_id):
    """Return the user row for a user id, or None."""
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def get_bank_details(user_id):
    """Return the bank details row for a user id, or None."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM bank_details WHERE user_id = ?", (user_id,)
        ).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def save_bank_details(user_id, account_holder, bank_name, ifsc, account_last4):
    """Insert or update the bank details row for a user, storing only last four."""
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO bank_details "
            "(user_id, account_holder, bank_name, ifsc, account_last4, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "account_holder = excluded.account_holder, "
            "bank_name = excluded.bank_name, "
            "ifsc = excluded.ifsc, "
            "account_last4 = excluded.account_last4, "
            "updated_at = excluded.updated_at",
            (user_id, account_holder, bank_name, ifsc, account_last4, _now_iso()),
        )
        conn.commit()
    finally:
        conn.close()


def store_login_code(phone, code, ttl_seconds=CODE_TTL_SECONDS):
    """Store a hashed demonstration code for a phone number with an expiry."""
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO login_codes (phone, code_hash, expires_at, attempts) "
            "VALUES (?, ?, ?, 0) "
            "ON CONFLICT(phone) DO UPDATE SET "
            "code_hash = excluded.code_hash, "
            "expires_at = excluded.expires_at, "
            "attempts = 0",
            (phone, hash_code(code), time.time() + ttl_seconds),
        )
        conn.commit()
    finally:
        conn.close()


def get_login_code(phone):
    """Return the stored code row for a phone number, or None."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM login_codes WHERE phone = ?", (phone,)
        ).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def increment_login_attempts(phone):
    """Increase the failed-attempt counter for a phone number's code."""
    conn = connect()
    try:
        conn.execute(
            "UPDATE login_codes SET attempts = attempts + 1 WHERE phone = ?", (phone,)
        )
        conn.commit()
    finally:
        conn.close()


def delete_login_code(phone):
    """Remove any stored code for a phone number."""
    conn = connect()
    try:
        conn.execute("DELETE FROM login_codes WHERE phone = ?", (phone,))
        conn.commit()
    finally:
        conn.close()


def delete_user(user_id):
    """Delete a user and all related rows, returning True when a row was removed."""
    conn = connect()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            return False
        conn.execute("DELETE FROM bank_details WHERE user_id = ?", (user_id,))
        if user["phone"]:
            conn.execute("DELETE FROM login_codes WHERE phone = ?", (user["phone"],))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()
