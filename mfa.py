"""
SecureAuth - Multi-Factor Authentication Core
Implements: TOTP (RFC 6238), HOTP, backup codes, session JWT management,
            brute-force protection, device fingerprinting
"""

import os
import io
import secrets
import hashlib
import time
import jwt
import pyotp
import qrcode
import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional


# ── JWT signing key — load from env in production ─────────────────────────────
_JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
_JWT_ALGO   = "HS256"
_JWT_ACCESS_EXPIRY  = 15     # minutes
_JWT_REFRESH_EXPIRY = 10080  # 7 days in minutes


@dataclass
class TOTPSetup:
    secret: str          # base32 encoded secret
    uri: str             # otpauth:// URI
    qr_base64: str       # base64 PNG QR code


@dataclass
class MFAVerifyResult:
    success: bool
    method: str
    message: str
    remaining_attempts: Optional[int] = None


@dataclass
class SessionTokens:
    access_token: str
    refresh_token: str
    expires_in: int      # seconds


# ── TOTP ──────────────────────────────────────────────────────────────────────

def generate_totp_setup(username: str, issuer: str = "SecureAuth") -> TOTPSetup:
    """
    Generate a new TOTP secret for a user.
    Returns secret, provisioning URI, and QR code PNG as base64.
    """
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(name=username, issuer_name=issuer)

    # Generate QR code
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return TOTPSetup(secret=secret, uri=uri, qr_base64=qr_b64)


def verify_totp(secret: str, token: str,
                valid_window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP token.
    valid_window=1 accepts 1 step before/after (clock drift tolerance).
    """
    if not token or not token.isdigit() or len(token) != 6:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=valid_window)


def get_current_totp(secret: str) -> dict:
    """Return the current TOTP token and remaining seconds (for testing/admin)."""
    totp = pyotp.TOTP(secret)
    remaining = 30 - (int(time.time()) % 30)
    return {"token": totp.now(), "remaining_seconds": remaining}


# ── Backup codes ──────────────────────────────────────────────────────────────

def generate_backup_codes(count: int = 10) -> list[str]:
    """
    Generate one-time backup codes.
    Format: XXXXX-XXXXX (10 alphanumeric chars, hyphen-separated).
    Returns plain codes — caller must hash and store.
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/I/1 ambiguity
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_backup_code(code: str) -> str:
    """SHA-256 hash a backup code for storage (they're long enough to hash directly)."""
    normalized = code.replace("-", "").upper()
    return hashlib.sha256(normalized.encode()).hexdigest()


def verify_backup_code(stored_hashes: list[str], candidate: str) -> tuple[bool, str | None]:
    """
    Verify a backup code against stored hashes.
    Returns (matched, matched_hash) — caller removes matched_hash from store.
    """
    normalized = candidate.replace("-", "").upper()
    candidate_hash = hashlib.sha256(normalized.encode()).hexdigest()
    for stored in stored_hashes:
        if hmac_compare(stored, candidate_hash):
            return True, stored
    return False, None


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return secrets.compare_digest(a.encode(), b.encode())


# ── Brute-force protection ────────────────────────────────────────────────────

class MFARateLimit:
    """
    In-memory rate limiter for MFA attempts.
    In production, replace with Redis-backed store.
    """
    MAX_ATTEMPTS = 5
    LOCKOUT_SECONDS = 900   # 15 minutes

    def __init__(self):
        self._store: dict[str, dict] = {}

    def _key(self, user_id: str, method: str) -> str:
        return f"{user_id}:{method}"

    def record_attempt(self, user_id: str, method: str, success: bool) -> dict:
        key = self._key(user_id, method)
        now = time.time()
        rec = self._store.get(key, {"attempts": 0, "locked_until": 0})

        if rec["locked_until"] > now:
            return {"allowed": False,
                    "locked_until": rec["locked_until"],
                    "remaining": int(rec["locked_until"] - now)}

        if success:
            self._store.pop(key, None)
            return {"allowed": True}

        rec["attempts"] += 1
        if rec["attempts"] >= self.MAX_ATTEMPTS:
            rec["locked_until"] = now + self.LOCKOUT_SECONDS
        self._store[key] = rec
        remaining = max(0, self.MAX_ATTEMPTS - rec["attempts"])
        return {"allowed": True, "attempts": rec["attempts"],
                "remaining_attempts": remaining}

    def is_locked(self, user_id: str, method: str) -> bool:
        key = self._key(user_id, method)
        rec = self._store.get(key)
        if not rec:
            return False
        return rec.get("locked_until", 0) > time.time()

    def get_status(self, user_id: str, method: str) -> dict:
        key = self._key(user_id, method)
        rec = self._store.get(key, {"attempts": 0, "locked_until": 0})
        now = time.time()
        locked = rec["locked_until"] > now
        return {
            "attempts": rec["attempts"],
            "locked": locked,
            "locked_until": rec["locked_until"] if locked else None,
            "remaining_attempts": max(0, self.MAX_ATTEMPTS - rec["attempts"]) if not locked else 0,
        }


_mfa_rate_limit = MFARateLimit()


# ── JWT session tokens ────────────────────────────────────────────────────────

def issue_tokens(user_id: str, username: str, role: str,
                 mfa_verified: bool = False) -> SessionTokens:
    """Issue a signed JWT access + refresh token pair."""
    now = datetime.now(timezone.utc)

    access_payload = {
        "sub":          user_id,
        "username":     username,
        "role":         role,
        "mfa_verified": mfa_verified,
        "iat":          now,
        "exp":          now + timedelta(minutes=_JWT_ACCESS_EXPIRY),
        "type":         "access",
        "jti":          secrets.token_hex(16),  # unique token ID
    }

    refresh_payload = {
        "sub":  user_id,
        "iat":  now,
        "exp":  now + timedelta(minutes=_JWT_REFRESH_EXPIRY),
        "type": "refresh",
        "jti":  secrets.token_hex(16),
    }

    access_token  = jwt.encode(access_payload,  _JWT_SECRET, algorithm=_JWT_ALGO)
    refresh_token = jwt.encode(refresh_payload, _JWT_SECRET, algorithm=_JWT_ALGO)

    return SessionTokens(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=_JWT_ACCESS_EXPIRY * 60,
    )


def verify_token(token: str, token_type: str = "access") -> dict:
    """
    Verify and decode a JWT.
    Returns decoded payload or raises jwt.PyJWTError.
    """
    payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGO])
    if payload.get("type") != token_type:
        raise jwt.InvalidTokenError("Wrong token type")
    return payload


def refresh_access_token(refresh_token: str, users_db: dict) -> SessionTokens:
    """Exchange a valid refresh token for a new access + refresh pair."""
    payload = verify_token(refresh_token, "refresh")
    user_id = payload["sub"]
    user = users_db.get(user_id)
    if not user:
        raise ValueError("User not found")
    return issue_tokens(user_id, user["username"], user["role"],
                        mfa_verified=user.get("mfa_enabled", False))


# ── Device fingerprint ────────────────────────────────────────────────────────

def fingerprint_device(ip: str, user_agent: str, user_id: str) -> str:
    """
    Create a pseudo-fingerprint from IP + UA + user-specific salt.
    Not a full browser fingerprint — used as a lightweight known-device signal.
    """
    raw = f"{ip}|{user_agent}|{user_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


import hmac as _hmac
