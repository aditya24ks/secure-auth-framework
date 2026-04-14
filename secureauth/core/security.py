"""
SecureAuth - Security Hardening Layer
Implements: Input validation / buffer-overflow prevention, privilege
            escalation detection, RBAC enforcement, audit logging,
            trapdoor/backdoor scanning, rate limiting
"""

import re
import os
import sys
import time
import hashlib
import secrets
import logging
import platform
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Callable
from functools import wraps
from enum import Enum


# ── Audit log ─────────────────────────────────────────────────────────────────

class AuditLevel(Enum):
    INFO    = "INFO"
    WARN    = "WARN"
    FAIL    = "FAIL"
    CRIT    = "CRIT"

@dataclass
class AuditEvent:
    timestamp: str
    level: AuditLevel
    category: str
    message: str
    user_id: Optional[str]
    ip: Optional[str]
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "level":     self.level.value,
            "category":  self.category,
            "message":   self.message,
            "user_id":   self.user_id,
            "ip":        self.ip,
            "details":   self.details,
        }


class AuditLogger:
    """
    Append-only, tamper-evident audit log.
    Each entry is chained to the previous via HMAC — any modification
    breaks the chain and is detectable by verify_chain().
    """
    def __init__(self, chain_secret: bytes = b"audit-chain-secret"):
        self._events: list[AuditEvent]  = []
        self._chain:  list[str]         = []
        self._secret  = chain_secret
        self._prev_hash = "GENESIS"

    def log(self, level: AuditLevel, category: str, message: str,
            user_id: str = None, ip: str = None, **details) -> AuditEvent:
        import hmac as _hmac
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level,
            category=category,
            message=message,
            user_id=user_id,
            ip=ip,
            details=details,
        )
        # Chain: HMAC(prev_hash + event_json)
        import json
        chain_input = (self._prev_hash + json.dumps(event.to_dict())).encode()
        self._prev_hash = _hmac.new(
            self._secret, chain_input, hashlib.sha256
        ).hexdigest()
        self._events.append(event)
        self._chain.append(self._prev_hash)
        return event

    def verify_chain(self) -> bool:
        """Verify no entries have been tampered with."""
        import hmac as _hmac, json
        prev = "GENESIS"
        for event, stored_hash in zip(self._events, self._chain):
            chain_input = (prev + json.dumps(event.to_dict())).encode()
            computed = _hmac.new(self._secret, chain_input, hashlib.sha256).hexdigest()
            if not secrets.compare_digest(computed, stored_hash):
                return False
            prev = computed
        return True

    def get_events(self, limit: int = 100, category: str = None,
                   level: AuditLevel = None) -> list[dict]:
        events = self._events[-limit:]
        if category:
            events = [e for e in events if e.category == category]
        if level:
            events = [e for e in events if e.level == level]
        return [e.to_dict() for e in reversed(events)]

    @property
    def count(self) -> int:
        return len(self._events)


audit = AuditLogger()


# ── Input validation — buffer overflow / injection prevention ─────────────────

# Hard limits for every untrusted input field
INPUT_LIMITS = {
    "username":   (1, 64),
    "password":   (1, 256),
    "email":      (5, 254),
    "token":      (6, 8),
    "code":       (11, 11),   # backup code: XXXXX-XXXXX
    "generic":    (0, 4096),
}

# Compiled allowlist patterns
SAFE_USERNAME = re.compile(r"^[a-zA-Z0-9._@\-]{1,64}$")
SAFE_EMAIL    = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
SAFE_TOKEN    = re.compile(r"^\d{6,8}$")


@dataclass
class ValidationResult:
    valid: bool
    sanitized: Optional[str] = None
    error: Optional[str] = None


def validate_input(value: str, field_type: str = "generic",
                   strict: bool = False) -> ValidationResult:
    """
    Validate and sanitize user input.
    Enforces hard length limits (buffer overflow protection at app layer),
    allowlist patterns, and null-byte / control-char stripping.
    """
    if not isinstance(value, str):
        return ValidationResult(False, None, "Input must be a string")

    # Strip null bytes and control characters (common in overflow attempts)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

    if sanitized != value:
        audit.log(AuditLevel.WARN, "INPUT_VALIDATION",
                  f"Control characters stripped from {field_type} field",
                  details={"original_len": len(value), "stripped_len": len(sanitized)})

    min_len, max_len = INPUT_LIMITS.get(field_type, INPUT_LIMITS["generic"])

    if len(sanitized) < min_len:
        return ValidationResult(False, None,
                                f"{field_type} must be at least {min_len} characters")
    if len(sanitized) > max_len:
        audit.log(AuditLevel.WARN, "INPUT_VALIDATION",
                  f"Oversized input rejected for field '{field_type}'",
                  details={"length": len(sanitized), "max": max_len})
        return ValidationResult(False, None,
                                f"{field_type} exceeds maximum length of {max_len}")

    if strict:
        if field_type == "username" and not SAFE_USERNAME.match(sanitized):
            return ValidationResult(False, None, "Username contains invalid characters")
        if field_type == "email" and not SAFE_EMAIL.match(sanitized):
            return ValidationResult(False, None, "Invalid email format")
        if field_type == "token" and not SAFE_TOKEN.match(sanitized):
            return ValidationResult(False, None, "Token must be 6–8 digits")

    return ValidationResult(True, sanitized, None)


def sanitize_for_log(value: str, max_len: int = 80) -> str:
    """Sanitize a value before writing to logs (prevent log injection)."""
    clean = re.sub(r"[\r\n\t]", " ", str(value))
    return clean[:max_len] + ("…" if len(clean) > max_len else "")


# ── RBAC — Privilege escalation prevention ────────────────────────────────────

class Role(Enum):
    VIEWER    = 0
    USER      = 1
    ANALYST   = 2
    DEVELOPER = 3
    ADMIN     = 4
    SUPERADMIN = 5


# Permission registry
PERMISSIONS: dict[str, set[Role]] = {
    # Auth
    "auth:login":           {Role.VIEWER, Role.USER, Role.ANALYST,
                              Role.DEVELOPER, Role.ADMIN, Role.SUPERADMIN},
    "auth:logout":          {Role.VIEWER, Role.USER, Role.ANALYST,
                              Role.DEVELOPER, Role.ADMIN, Role.SUPERADMIN},
    # User management
    "users:read_self":      {Role.USER, Role.ANALYST, Role.DEVELOPER,
                              Role.ADMIN, Role.SUPERADMIN},
    "users:read_all":       {Role.ANALYST, Role.DEVELOPER, Role.ADMIN, Role.SUPERADMIN},
    "users:create":         {Role.ADMIN, Role.SUPERADMIN},
    "users:delete":         {Role.SUPERADMIN},
    "users:lock_unlock":    {Role.ADMIN, Role.SUPERADMIN},
    "users:change_role":    {Role.SUPERADMIN},
    # MFA
    "mfa:setup_self":       {Role.USER, Role.ANALYST, Role.DEVELOPER,
                              Role.ADMIN, Role.SUPERADMIN},
    "mfa:revoke_other":     {Role.ADMIN, Role.SUPERADMIN},
    # Audit
    "audit:read":           {Role.ANALYST, Role.ADMIN, Role.SUPERADMIN},
    "audit:export":         {Role.ADMIN, Role.SUPERADMIN},
    # Security
    "security:run_scan":    {Role.ADMIN, Role.SUPERADMIN},
    "security:config":      {Role.SUPERADMIN},
    # Password policy
    "policy:read":          {Role.ANALYST, Role.ADMIN, Role.SUPERADMIN},
    "policy:write":         {Role.ADMIN, Role.SUPERADMIN},
}


def check_permission(role_str: str, permission: str) -> bool:
    """Return True if the given role holds the requested permission."""
    try:
        role = Role[role_str.upper()]
    except KeyError:
        audit.log(AuditLevel.WARN, "PRIVILEGE",
                  f"Unknown role '{sanitize_for_log(role_str)}' used in permission check",
                  details={"permission": permission})
        return False

    allowed_roles = PERMISSIONS.get(permission, set())
    granted = role in allowed_roles

    if not granted:
        audit.log(AuditLevel.WARN, "PRIVILEGE",
                  f"Permission denied: {role_str} → {permission}",
                  details={"role": role_str, "permission": permission})
    return granted


def require_permission(permission: str):
    """Decorator: guard a Flask route with a permission check."""
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify
            from .mfa import verify_token
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing token"}), 401
            try:
                payload = verify_token(auth_header[7:])
            except Exception:
                return jsonify({"error": "Invalid or expired token"}), 401

            role = payload.get("role", "")
            user_id = payload.get("sub", "")

            if not check_permission(role, permission):
                audit.log(AuditLevel.CRIT, "PRIVILEGE",
                          f"Privilege escalation attempt: {permission}",
                          user_id=user_id,
                          ip=request.remote_addr,
                          role=role, permission=permission)
                return jsonify({"error": "Insufficient privileges"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── Backdoor / trapdoor scanner ───────────────────────────────────────────────

TRAPDOOR_SIGNATURES = [
    # Hardcoded credential patterns
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
     "Hardcoded password literal"),
    (r'(?i)(secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded secret/API key"),
    (r'(?i)admin.*admin|root.*root|test.*test',
     "Suspicious default credential pattern"),
    # Hidden exec / shell injection vectors
    (r'(?i)(eval|exec)\s*\(',
     "Dynamic code execution (eval/exec)"),
    (r'(?i)os\.system\s*\(',
     "Direct shell execution (os.system)"),
    (r'(?i)subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
     "Shell=True in subprocess call"),
    # Backdoor network patterns
    (r'(?i)(bind|listen|accept)\s*\(\s*["\']?0\.0\.0\.0',
     "Binding to all interfaces (0.0.0.0)"),
    (r'(?i)import\s+socket.*connect\s*\(',
     "Outbound socket connection"),
    # Debug / maintenance backdoors
    (r'(?i)debug\s*=\s*True',
     "Debug mode enabled"),
    (r'(?i)#\s*(backdoor|trapdoor|hack|pwn|bypass)',
     "Suspicious comment keyword"),
]

@dataclass
class ScanFinding:
    severity: str
    file: str
    line: int
    pattern: str
    description: str
    snippet: str


def scan_for_trapdoors(path: str = ".") -> list[ScanFinding]:
    """
    Static-analysis scan for trapdoor/backdoor signatures in Python files.
    Returns a list of ScanFindings.
    """
    findings: list[ScanFinding] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__",
                                                  "node_modules", ".venv"}]
        for fname in files:
            if not fname.endswith((".py", ".js", ".sh", ".php", ".rb")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (IOError, OSError):
                continue

            for lineno, line in enumerate(lines, 1):
                for pattern, description in TRAPDOOR_SIGNATURES:
                    if re.search(pattern, line):
                        severity = "CRITICAL" if "hardcoded" in description.lower() \
                                               or "debug" in description.lower() \
                                   else "HIGH"
                        findings.append(ScanFinding(
                            severity=severity,
                            file=fpath,
                            line=lineno,
                            pattern=pattern,
                            description=description,
                            snippet=line.strip()[:120],
                        ))
    if findings:
        audit.log(AuditLevel.CRIT, "SCAN",
                  f"Trapdoor scan found {len(findings)} finding(s)",
                  details={"count": len(findings)})
    else:
        audit.log(AuditLevel.INFO, "SCAN",
                  "Trapdoor scan completed — no findings")
    return findings


# ── Privilege escalation monitoring ──────────────────────────────────────────

class PrivilegeMonitor:
    """
    Tracks role changes and detects anomalous privilege escalation patterns.
    """
    def __init__(self):
        self._role_history: dict[str, list[dict]] = {}

    def record_role_change(self, target_user_id: str,
                           from_role: str, to_role: str,
                           changed_by: str, ip: str = "") -> bool:
        """
        Record a role change and detect suspicious escalations.
        Returns False and blocks if escalation is anomalous.
        """
        from_val = Role[from_role.upper()].value if from_role.upper() in Role.__members__ else -1
        to_val   = Role[to_role.upper()].value   if to_role.upper()   in Role.__members__ else -1

        history = self._role_history.setdefault(target_user_id, [])

        # Multiple rapid escalations = suspicious
        recent_escalations = [
            h for h in history[-10:]
            if h.get("direction") == "up"
               and (time.time() - h.get("ts", 0)) < 3600
        ]

        event = {
            "ts":         time.time(),
            "from_role":  from_role,
            "to_role":    to_role,
            "changed_by": changed_by,
            "direction":  "up" if to_val > from_val else "down",
        }
        history.append(event)

        level = AuditLevel.INFO
        message = f"Role change: {target_user_id} {from_role} → {to_role} by {changed_by}"

        if to_val > from_val:
            level = AuditLevel.WARN
            if len(recent_escalations) >= 2:
                level = AuditLevel.CRIT
                message = f"ANOMALOUS privilege escalation pattern detected for {target_user_id}"

        audit.log(level, "PRIVILEGE", message,
                  user_id=changed_by, ip=ip,
                  target=target_user_id,
                  from_role=from_role, to_role=to_role)

        return level != AuditLevel.CRIT

    def get_history(self, user_id: str) -> list[dict]:
        return self._role_history.get(user_id, [])


privilege_monitor = PrivilegeMonitor()


# ── Security headers helper ───────────────────────────────────────────────────

SECURITY_HEADERS = {
    "X-Frame-Options":           "DENY",
    "X-Content-Type-Options":    "nosniff",
    "X-XSS-Protection":          "1; mode=block",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy":   (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
        "font-src fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    ),
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
}

def apply_security_headers(response):
    """Apply all security headers to a Flask response."""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response
