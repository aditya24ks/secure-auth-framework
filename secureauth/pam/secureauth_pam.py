"""
SecureAuth - Linux PAM Module Integration
-----------------------------------------
This module provides a Python-based PAM authentication handler that
integrates SecureAuth's MFA and policy enforcement into the OS login stack.

INSTALLATION (Linux, requires root):
  1. Copy this file to /usr/lib/security/secureauth_pam.py
  2. Add to /etc/pam.d/sshd (or any service):
       auth required pam_python.so /usr/lib/security/secureauth_pam.py
  3. Install pam_python: apt install libpam-python

PAM MODULE FLOW:
  pam_sm_authenticate → validates credentials via SecureAuth core
  pam_sm_acct_mgmt   → checks account status, MFA enrollment
  pam_sm_setcred     → sets environment for the session
"""

import os
import sys
import syslog
import time

# Allow import of secureauth core from this module
_SA_PATH = os.environ.get("SECUREAUTH_PATH", "/opt/secureauth")
if _SA_PATH not in sys.path:
    sys.path.insert(0, _SA_PATH)

try:
    from core.password_manager import verify_password, analyze_password
    from core.mfa import verify_totp, _mfa_rate_limit
    from core.security import audit, AuditLevel, validate_input
    _CORE_AVAILABLE = True
except ImportError:
    _CORE_AVAILABLE = False

# ── PAM return codes ──────────────────────────────────────────────────────────
PAM_SUCCESS       = 0
PAM_AUTH_ERR      = 7
PAM_ACCT_EXPIRED  = 13
PAM_USER_UNKNOWN  = 10
PAM_MAXTRIES      = 8
PAM_IGNORE        = 25


def _log(level, msg):
    priority = {
        "info":  syslog.LOG_INFO,
        "warn":  syslog.LOG_WARNING,
        "err":   syslog.LOG_ERR,
        "crit":  syslog.LOG_CRIT,
    }.get(level, syslog.LOG_INFO)
    syslog.openlog("secureauth-pam", syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(priority, f"[SecureAuth] {msg}")
    syslog.closelog()


def _load_user_db():
    """
    Load user records from the SecureAuth user store.
    In production this connects to a DB/API; here we load from a JSON file.
    """
    import json
    db_path = os.path.join(_SA_PATH, "data", "users.json")
    if not os.path.isfile(db_path):
        return {}
    try:
        with open(db_path) as f:
            return json.load(f)
    except (IOError, ValueError):
        return {}


# ── PAM hooks ─────────────────────────────────────────────────────────────────

def pam_sm_authenticate(pamh, flags, argv):
    """
    Primary authentication handler.
    Called by PAM when a user attempts to log in.
    """
    if not _CORE_AVAILABLE:
        _log("err", "SecureAuth core not importable — falling back to PAM_IGNORE")
        return PAM_IGNORE

    try:
        username = pamh.get_user(None)
    except pamh.exception:
        return PAM_USER_UNKNOWN

    if not username:
        return PAM_USER_UNKNOWN

    # Validate input length (buffer overflow protection)
    v = validate_input(username, "username", strict=True)
    if not v.valid:
        _log("warn", f"Invalid username format from PAM: {username[:32]!r}")
        return PAM_AUTH_ERR

    # Rate-limit check
    if _mfa_rate_limit.is_locked(username, "pam"):
        _log("warn", f"PAM auth blocked — rate limited: {username}")
        return PAM_MAXTRIES

    # Get password via PAM conversation
    try:
        msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Password: ")
        resp = pamh.conversation(msg)
        password = resp.resp
    except pamh.exception:
        return PAM_AUTH_ERR

    if not password:
        return PAM_AUTH_ERR

    # Load user record
    db = _load_user_db()
    user = db.get(username)
    if not user:
        # Still do a dummy verify to prevent timing oracle
        verify_password("$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy", password)
        _log("warn", f"PAM auth failed — unknown user: {username}")
        return PAM_USER_UNKNOWN

    # Account lockout
    if user.get("locked_until", 0) > time.time():
        _log("warn", f"PAM auth denied — account locked: {username}")
        return PAM_AUTH_ERR

    # Password verification (Argon2id, timing-safe)
    if not verify_password(user["password_hash"], password):
        _mfa_rate_limit.record_attempt(username, "pam", False)
        _log("warn", f"PAM auth failed — wrong password: {username}")
        if audit:
            audit.log(AuditLevel.WARN, "PAM_AUTH",
                      f"PAM password failure: {username}")
        return PAM_AUTH_ERR

    # MFA check (if enrolled)
    if user.get("mfa_enabled") and user.get("mfa_secret"):
        try:
            msg = pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "SecureAuth MFA Code: ")
            resp = pamh.conversation(msg)
            mfa_token = (resp.resp or "").strip()
        except pamh.exception:
            return PAM_AUTH_ERR

        if not verify_totp(user["mfa_secret"], mfa_token):
            _mfa_rate_limit.record_attempt(username, "pam", False)
            _log("warn", f"PAM MFA failed: {username}")
            return PAM_AUTH_ERR

    _mfa_rate_limit.record_attempt(username, "pam", True)
    _log("info", f"PAM auth success: {username}")
    if audit:
        audit.log(AuditLevel.INFO, "PAM_AUTH", f"PAM authentication success: {username}")
    return PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    """Set credentials after authentication — no-op for this module."""
    return PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    """
    Account management: verify account is active and not expired.
    Called after authentication to decide if the session should proceed.
    """
    try:
        username = pamh.get_user(None)
    except pamh.exception:
        return PAM_USER_UNKNOWN

    db = _load_user_db()
    user = db.get(username)
    if not user:
        return PAM_USER_UNKNOWN
    if not user.get("active", True):
        _log("warn", f"PAM acct_mgmt denied — inactive: {username}")
        return PAM_ACCT_EXPIRED

    return PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    """Session opened — log it."""
    try:
        username = pamh.get_user(None)
        _log("info", f"PAM session opened: {username}")
    except pamh.exception:
        pass
    return PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    """Session closed — log it."""
    try:
        username = pamh.get_user(None)
        _log("info", f"PAM session closed: {username}")
    except pamh.exception:
        pass
    return PAM_SUCCESS
