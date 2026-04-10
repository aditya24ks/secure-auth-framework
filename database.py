"""
SecureAuth - Database Layer
SQLite-backed persistent storage for users, audit events, MFA secrets.
Replaces the in-memory dict store in api/server.py for production use.

Usage:
    from core.database import Database
    db = Database("secureauth.db")
    db.init()
"""

import sqlite3
import time
import json
import secrets
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Optional


class Database:
    def __init__(self, db_path: str = "secureauth.db"):
        self.db_path = db_path
        self._init_done = False

    @contextmanager
    def conn(self):
        """Thread-safe context manager yielding a DB connection."""
        con = sqlite3.connect(self.db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def init(self):
        """Create all tables if they don't exist."""
        with self.conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id               TEXT PRIMARY KEY,
                username         TEXT UNIQUE NOT NULL,
                email            TEXT,
                role             TEXT NOT NULL DEFAULT 'USER',
                password_hash    TEXT NOT NULL,
                mfa_enabled      INTEGER NOT NULL DEFAULT 0,
                mfa_secret       TEXT,
                backup_code_hashes TEXT DEFAULT '[]',
                failed_attempts  INTEGER NOT NULL DEFAULT 0,
                locked_until     REAL NOT NULL DEFAULT 0,
                created_at       REAL NOT NULL,
                last_login       REAL,
                password_history TEXT DEFAULT '[]',
                active           INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                level       TEXT NOT NULL,
                category    TEXT NOT NULL,
                message     TEXT NOT NULL,
                user_id     TEXT,
                ip          TEXT,
                details     TEXT DEFAULT '{}',
                chain_hash  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                jti         TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL,
                revoked     INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS password_resets (
                token       TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL,
                used        INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_users_username   ON users(username);
            CREATE INDEX IF NOT EXISTS idx_audit_category   ON audit_events(category);
            CREATE INDEX IF NOT EXISTS idx_audit_user       ON audit_events(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
            """)
        self._init_done = True

    # ── User operations ───────────────────────────────────────────────────────

    def create_user(self, username: str, password_hash: str,
                    role: str = "USER", email: str = "") -> str:
        uid = secrets.token_hex(8)
        with self.conn() as c:
            c.execute("""
                INSERT INTO users (id, username, email, role, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (uid, username, email, role, password_hash, time.time()))
        return uid

    def get_user_by_username(self, username: str) -> Optional[dict]:
        with self.conn() as c:
            row = c.execute("SELECT * FROM users WHERE username=?",
                            (username,)).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        with self.conn() as c:
            row = c.execute("SELECT * FROM users WHERE id=?",
                            (user_id,)).fetchone()
        if not row:
            return None
        u = dict(row)
        u["backup_code_hashes"] = json.loads(u.get("backup_code_hashes") or "[]")
        u["password_history"]   = json.loads(u.get("password_history") or "[]")
        return u

    def list_users(self) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("""
                SELECT id, username, email, role, mfa_enabled,
                       locked_until, last_login, created_at, active
                FROM users ORDER BY created_at DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def update_user(self, user_id: str, **fields) -> bool:
        """Update arbitrary user fields. JSON-serialises list values."""
        if not fields:
            return False
        # Serialise lists
        for k, v in fields.items():
            if isinstance(v, list):
                fields[k] = json.dumps(v)
        set_clause = ", ".join(f"{k}=?" for k in fields)
        values     = list(fields.values()) + [user_id]
        with self.conn() as c:
            c.execute(f"UPDATE users SET {set_clause} WHERE id=?", values)
        return True

    def record_login_success(self, user_id: str):
        self.update_user(user_id, failed_attempts=0, last_login=time.time())

    def record_login_failure(self, user_id: str, max_attempts: int = 5,
                              lockout_seconds: int = 900) -> dict:
        u = self.get_user_by_id(user_id)
        if not u:
            return {"locked": False, "attempts": 0}
        new_attempts = u["failed_attempts"] + 1
        locked_until = 0.0
        if new_attempts >= max_attempts:
            locked_until = time.time() + lockout_seconds
        self.update_user(user_id,
                         failed_attempts=new_attempts,
                         locked_until=locked_until)
        return {"locked": locked_until > 0, "attempts": new_attempts,
                "locked_until": locked_until}

    # ── MFA operations ────────────────────────────────────────────────────────

    def set_mfa_secret(self, user_id: str, secret: str,
                       backup_hashes: list[str]):
        self.update_user(user_id,
                         mfa_enabled=1,
                         mfa_secret=secret,
                         backup_code_hashes=json.dumps(backup_hashes))

    def disable_mfa(self, user_id: str):
        self.update_user(user_id,
                         mfa_enabled=0,
                         mfa_secret=None,
                         backup_code_hashes="[]")

    def consume_backup_code(self, user_id: str, matched_hash: str) -> bool:
        u = self.get_user_by_id(user_id)
        if not u:
            return False
        hashes = u["backup_code_hashes"]
        if matched_hash not in hashes:
            return False
        hashes.remove(matched_hash)
        self.update_user(user_id, backup_code_hashes=json.dumps(hashes))
        return True

    # ── Session / JTI revocation ──────────────────────────────────────────────

    def register_session(self, jti: str, user_id: str, expires_at: float):
        with self.conn() as c:
            c.execute("""
                INSERT INTO sessions (jti, user_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            """, (jti, user_id, time.time(), expires_at))

    def revoke_session(self, jti: str):
        with self.conn() as c:
            c.execute("UPDATE sessions SET revoked=1 WHERE jti=?", (jti,))

    def is_session_valid(self, jti: str) -> bool:
        with self.conn() as c:
            row = c.execute("""
                SELECT revoked, expires_at FROM sessions WHERE jti=?
            """, (jti,)).fetchone()
        if not row:
            return False
        return not row["revoked"] and row["expires_at"] > time.time()

    def purge_expired_sessions(self):
        with self.conn() as c:
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))

    # ── Audit persistence ─────────────────────────────────────────────────────

    def persist_audit_event(self, event_dict: dict, chain_hash: str):
        with self.conn() as c:
            c.execute("""
                INSERT INTO audit_events
                    (timestamp, level, category, message, user_id, ip, details, chain_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_dict["timestamp"],
                event_dict["level"],
                event_dict["category"],
                event_dict["message"],
                event_dict.get("user_id"),
                event_dict.get("ip"),
                json.dumps(event_dict.get("details", {})),
                chain_hash,
            ))

    def get_audit_events(self, limit: int = 100,
                          category: str = None) -> list[dict]:
        query  = "SELECT * FROM audit_events"
        params: list = []
        if category:
            query  += " WHERE category=?"
            params.append(category)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self.conn() as c:
            rows = c.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def verify_audit_chain_db(self) -> bool:
        """Verify the HMAC chain stored in the database."""
        import hmac as _hmac, hashlib
        _secret = b"audit-chain-secret"
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM audit_events ORDER BY id ASC"
            ).fetchall()
        prev = "GENESIS"
        for row in rows:
            event_json = json.dumps({
                "timestamp": row["timestamp"],
                "level":     row["level"],
                "category":  row["category"],
                "message":   row["message"],
                "user_id":   row["user_id"],
                "ip":        row["ip"],
                "details":   json.loads(row["details"] or "{}"),
            })
            computed = _hmac.new(
                _secret, (prev + event_json).encode(), hashlib.sha256
            ).hexdigest()
            if not secrets.compare_digest(computed, row["chain_hash"]):
                return False
            prev = computed
        return True


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name

    db = Database(path)
    db.init()

    uid = db.create_user("alice", "hashed_password_here", "ADMIN", "alice@test.com")
    print(f"Created user: {uid}")

    u = db.get_user_by_username("alice")
    print(f"Retrieved: {u['username']} / {u['role']}")

    res = db.record_login_failure(uid, max_attempts=3)
    print(f"After 1 failure: {res}")

    db.persist_audit_event({
        "timestamp": "2024-01-01T00:00:00+00:00",
        "level": "INFO", "category": "AUTH",
        "message": "Test event", "user_id": uid,
        "ip": "127.0.0.1", "details": {}
    }, "genesis_hash")
    events = db.get_audit_events(limit=5)
    print(f"Audit events: {len(events)}")

    os.unlink(path)
    print("Database layer OK")
