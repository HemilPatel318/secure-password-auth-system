import os
import sqlite3

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    # Reuse one connection per request and expose rows by column name.
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DB_PATH"])
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def close_db(_exc=None) -> None:
    # Close the request-scoped connection if one was opened.
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path: str) -> None:
    # Bootstrap the SQLite database the first time the app starts.
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lock_until TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.execute(
        """
        -- Stores the active OTP challenge for the second factor step.
        CREATE TABLE IF NOT EXISTS otp_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    conn.commit()
    conn.close()
