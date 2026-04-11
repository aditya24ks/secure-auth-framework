"""
SecureAuth - Password Management Core
Implements: Argon2id hashing, policy enforcement, strength analysis,
            timing-safe comparison, breach-pattern detection
"""

import re
import secrets
import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError


# ── Argon2id configuration (OWASP recommended params) ─────────────────────────
_PH = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# Server-side pepper — in production, load from HSM / env secret
_PEPPER = b"secureauth-pepper-change-in-prod-b2x9q7!"


@dataclass
class PasswordPolicy:
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    max_age_days: int = 90
    history_count: int = 10          # prevent reuse of last N passwords
    reject_common: bool = True       # dictionary / common pattern check
    reject_username_in_password: bool = True

    COMMON_PATTERNS = [
        r"^(.)\1+$",                 # all same char: aaaaaaa
        r"^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)",
        r"password", r"qwerty", r"letmein", r"welcome", r"admin",
        r"login", r"123456", r"iloveyou", r"monkey", r"dragon",
    ]


@dataclass
class PasswordAnalysis:
    score: int           # 0-100
    strength: str        # very_weak / weak / fair / strong / very_strong
    entropy_bits: float
    passes_policy: bool
    violations: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


def _apply_pepper(password: str) -> str:
    """HMAC-SHA256 the password with the pepper before hashing."""
    return hmac.new(_PEPPER, password.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(password: str) -> str:
    """
    Hash a password with Argon2id + server pepper.
    Returns an opaque hash string safe to store in DB.
    """
    peppered = _apply_pepper(password)
    return _PH.hash(peppered)


def verify_password(stored_hash: str, candidate: str) -> bool:
    """
    Timing-safe password verification.
    Returns True on match; always takes a similar wall-clock time
    regardless of early mismatch (mitigates timing oracles).
    """
    peppered = _apply_pepper(candidate)
    # Run a dummy hash to normalise timing on failure paths
    _dummy_start = time.monotonic()
    try:
        result = _PH.verify(stored_hash, peppered)
        return result
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        # Burn time equivalent to a hash verify to prevent timing side-channel
        elapsed = time.monotonic() - _dummy_start
        target = 0.05  # ~50 ms minimum
        if elapsed < target:
            time.sleep(target - elapsed)
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Return True if the hash was created with old params and needs upgrade."""
    return _PH.check_needs_rehash(stored_hash)


def analyze_password(password: str, username: str = "",
                     policy: Optional[PasswordPolicy] = None) -> PasswordAnalysis:
    """
    Full password quality analysis against policy.
    Returns a PasswordAnalysis with score, entropy, violations, suggestions.
    """
    if policy is None:
        policy = PasswordPolicy()

    violations: list[str] = []
    suggestions: list[str] = []

    # ── Length ───────────────────────────────────────────────────────────────
    if len(password) < policy.min_length:
        violations.append(f"Minimum length is {policy.min_length} characters")
        suggestions.append(f"Add {policy.min_length - len(password)} more characters")
    if len(password) > policy.max_length:
        violations.append(f"Maximum length is {policy.max_length} characters")

    # ── Character class checks ────────────────────────────────────────────────
    has_upper   = bool(re.search(r"[A-Z]", password))
    has_lower   = bool(re.search(r"[a-z]", password))
    has_digit   = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    if policy.require_uppercase and not has_upper:
        violations.append("Must contain at least one uppercase letter")
    if policy.require_lowercase and not has_lower:
        violations.append("Must contain at least one lowercase letter")
    if policy.require_digits and not has_digit:
        violations.append("Must contain at least one digit")
    if policy.require_special and not has_special:
        violations.append("Must contain at least one special character")
        suggestions.append("Add symbols like !@#$%^&*()")

    # ── Common pattern detection ──────────────────────────────────────────────
    if policy.reject_common:
        pwd_lower = password.lower()
        for pattern in policy.COMMON_PATTERNS:
            if re.search(pattern, pwd_lower):
                violations.append("Password matches a commonly used pattern")
                suggestions.append("Avoid sequential characters, repeated characters, or common words")
                break

    # ── Username in password ──────────────────────────────────────────────────
    if policy.reject_username_in_password and username:
        if username.lower() in password.lower():
            violations.append("Password must not contain your username")

    # ── Entropy estimation ────────────────────────────────────────────────────
    pool = 0
    if has_lower:   pool += 26
    if has_upper:   pool += 26
    if has_digit:   pool += 10
    if has_special: pool += 32
    if pool == 0:   pool = 26
    import math
    entropy = len(password) * math.log2(pool)

    # ── Score (0–100) ─────────────────────────────────────────────────────────
    score = 0
    score += min(40, int(len(password) / policy.min_length * 25))
    score += 10 if has_upper   else 0
    score += 10 if has_lower   else 0
    score += 10 if has_digit   else 0
    score += 15 if has_special else 0
    score += min(15, int(entropy / 8))
    score -= len(violations) * 10
    score = max(0, min(100, score))

    strength_map = [
        (20,  "very_weak"),
        (40,  "weak"),
        (60,  "fair"),
        (80,  "strong"),
        (101, "very_strong"),
    ]
    strength = next(s for threshold, s in strength_map if score < threshold)

    if not suggestions and score < 80:
        suggestions.append("Use a passphrase with mixed words, numbers, and symbols")

    return PasswordAnalysis(
        score=score,
        strength=strength,
        entropy_bits=round(entropy, 1),
        passes_policy=len(violations) == 0,
        violations=violations,
        suggestions=suggestions,
    )


def generate_secure_password(length: int = 20) -> str:
    """Generate a cryptographically secure random password meeting default policy."""
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}|;:,.<>?"
    )
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        a = analyze_password(pwd)
        if a.passes_policy and a.score >= 80:
            return pwd
