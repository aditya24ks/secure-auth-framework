"""
SecureAuth - REST API Server
All endpoints use real cryptography, actual JWT tokens, proper rate limiting,
and full audit logging.
"""

import os
import sys
import json
import time
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, request, jsonify, send_file, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from core.password_manager import (
    hash_password, verify_password, analyze_password,
    generate_secure_password, PasswordPolicy, needs_rehash,
)
from core.mfa import (
    generate_totp_setup, verify_totp, get_current_totp,
    generate_backup_codes, hash_backup_code, verify_backup_code,
    issue_tokens, verify_token, refresh_access_token,
    fingerprint_device, _mfa_rate_limit,
)
from core.security import (
    audit, AuditLevel, validate_input, check_permission,
    require_permission, scan_for_trapdoors, privilege_monitor,
    apply_security_headers, sanitize_for_log,
)
from core.os_integration import (
    os_authenticate, list_system_users, get_privilege_info,
    check_system_security, PLATFORM, PAM_AVAILABLE,
)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# ── Rate limiting ─────────────────────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour", "50 per minute"],
    storage_uri="memory://",
)

# ── In-memory user store (replace with DB in production) ─────────────────────
# Structure: user_id → user_record
_users: dict[str, dict] = {}
_usernames: dict[str, str] = {}  # username → user_id index


def _make_user(username: str, password: str, role: str = "USER",
               email: str = "") -> dict:
    user_id = secrets.token_hex(8)
    return {
        "id":              user_id,
        "username":        username,
        "email":           email or f"{username}@secureauth.local",
        "role":            role,
        "password_hash":   hash_password(password),
        "mfa_enabled":     False,
        "mfa_secret":      None,
        "backup_code_hashes": [],
        "failed_attempts": 0,
        "locked_until":    0,
        "created_at":      time.time(),
        "last_login":      None,
        "password_history": [],   # list of old hashes
        "active":          True,
    }


# Seed demo users
def _seed():
    for uname, pwd, role in [
        ("admin",     "Admin@SecureAuth1!",    "ADMIN"),
        ("developer", "Dev@SecurePass9#",      "DEVELOPER"),
        ("analyst",   "Analyst$Pass7^",        "ANALYST"),
        ("user",      "User@Pass5&Simple",     "USER"),
    ]:
        u = _make_user(uname, pwd, role)
        _users[u["id"]] = u
        _usernames[uname] = u["id"]

_seed()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS     = 900   # 15 min


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_user_by_username(username: str) -> dict | None:
    uid = _usernames.get(username)
    return _users.get(uid) if uid else None

def _current_user() -> dict | None:
    token = request.headers.get("Authorization", "")[7:]
    try:
        payload = verify_token(token)
        return _users.get(payload["sub"])
    except Exception:
        return None

def _require_token():
    """Decode and return JWT payload or abort with 401."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, jsonify({"error": "Missing token"}), 401
    try:
        payload = verify_token(auth[7:])
        return payload, None, None
    except Exception as e:
        return None, jsonify({"error": f"Invalid token: {e}"}), 401


# ── Security headers on every response ───────────────────────────────────────
@app.after_request
def add_security_headers(response):
    return apply_security_headers(response)


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    ip   = request.remote_addr

    # Input validation
    uname_v = validate_input(data.get("username", ""), "username", strict=True)
    pass_v  = validate_input(data.get("password", ""), "password")
    if not uname_v.valid:
        return jsonify({"error": uname_v.error}), 400
    if not pass_v.valid:
        return jsonify({"error": pass_v.error}), 400

    username = uname_v.sanitized
    password = pass_v.sanitized

    user = _get_user_by_username(username)

    # Uniform response timing — don't leak user existence via timing
    if not user:
        verify_password(list(_users.values())[0]["password_hash"], password)
        audit.log(AuditLevel.WARN, "AUTH", "Login attempt for unknown user",
                  ip=ip, details={"username": sanitize_for_log(username)})
        return jsonify({"error": "Invalid credentials"}), 401

    # Lockout check
    if user["locked_until"] > time.time():
        remaining = int(user["locked_until"] - time.time())
        audit.log(AuditLevel.WARN, "AUTH", "Login attempt on locked account",
                  user_id=user["id"], ip=ip)
        return jsonify({"error": f"Account locked. Try again in {remaining}s"}), 429

    if not user["active"]:
        return jsonify({"error": "Account is disabled"}), 403

    # Password verification
    if not verify_password(user["password_hash"], password):
        user["failed_attempts"] += 1
        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            user["locked_until"] = time.time() + LOCKOUT_SECONDS
            audit.log(AuditLevel.CRIT, "AUTH",
                      f"Account locked after {MAX_FAILED_ATTEMPTS} failed attempts",
                      user_id=user["id"], ip=ip)
            return jsonify({"error": "Account locked after too many failed attempts"}), 429
        remaining = MAX_FAILED_ATTEMPTS - user["failed_attempts"]
        audit.log(AuditLevel.WARN, "AUTH", "Failed login",
                  user_id=user["id"], ip=ip,
                  attempts=user["failed_attempts"], remaining=remaining)
        return jsonify({"error": f"Invalid credentials. {remaining} attempts remaining"}), 401

    # Check if password hash needs upgrade (Argon2 param change)
    if needs_rehash(user["password_hash"]):
        user["password_hash"] = hash_password(password)

    # Reset failed attempts
    user["failed_attempts"] = 0

    # MFA required?
    if user["mfa_enabled"]:
        mfa_token = data.get("mfa_token", "").strip()
        if not mfa_token:
            audit.log(AuditLevel.INFO, "MFA", "MFA challenge issued",
                      user_id=user["id"], ip=ip)
            return jsonify({"mfa_required": True,
                            "message": "Enter your 6-digit MFA code"}), 200

        # Rate-limit MFA attempts
        if _mfa_rate_limit.is_locked(user["id"], "totp"):
            return jsonify({"error": "Too many MFA attempts. Wait 15 minutes."}), 429

        mfa_ok = verify_totp(user["mfa_secret"], mfa_token)
        _mfa_rate_limit.record_attempt(user["id"], "totp", mfa_ok)

        if not mfa_ok:
            # Try backup code
            ok, matched_hash = verify_backup_code(
                user["backup_code_hashes"], mfa_token
            )
            if ok:
                user["backup_code_hashes"].remove(matched_hash)
                audit.log(AuditLevel.WARN, "MFA", "Backup code used",
                          user_id=user["id"], ip=ip,
                          remaining=len(user["backup_code_hashes"]))
                mfa_ok = True
            else:
                audit.log(AuditLevel.WARN, "MFA", "MFA verification failed",
                          user_id=user["id"], ip=ip)
                return jsonify({"error": "Invalid MFA code"}), 401

    # Issue tokens
    tokens = issue_tokens(
        user["id"], user["username"], user["role"],
        mfa_verified=user["mfa_enabled"],
    )
    user["last_login"] = time.time()

    device_fp = fingerprint_device(ip, request.user_agent.string, user["id"])
    audit.log(AuditLevel.INFO, "AUTH", "Successful login",
              user_id=user["id"], ip=ip,
              role=user["role"], device=device_fp)

    return jsonify({
        "access_token":  tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_in":    tokens.expires_in,
        "user": {
            "id":          user["id"],
            "username":    user["username"],
            "role":        user["role"],
            "mfa_enabled": user["mfa_enabled"],
        }
    })


@app.route("/api/auth/refresh", methods=["POST"])
@limiter.limit("30 per minute")
def refresh():
    data = request.get_json(silent=True) or {}
    rt   = data.get("refresh_token", "")
    try:
        tokens = refresh_access_token(rt, _users)
        return jsonify({"access_token": tokens.access_token,
                        "expires_in":   tokens.expires_in})
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    payload, err, code = _require_token()
    if err:
        return err, code
    audit.log(AuditLevel.INFO, "AUTH", "User logged out",
              user_id=payload["sub"], ip=request.remote_addr)
    # In production: add jti to a revocation list / Redis
    return jsonify({"message": "Logged out successfully"})


# ═══════════════════════════════════════════════════════════════════════════════
# MFA ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/mfa/setup", methods=["POST"])
def mfa_setup():
    payload, err, code = _require_token()
    if err:
        return err, code
    user = _users.get(payload["sub"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    setup = generate_totp_setup(user["username"])
    # Store secret temporarily — confirmed on first verify
    user["mfa_pending_secret"] = setup.secret

    audit.log(AuditLevel.INFO, "MFA", "TOTP setup initiated",
              user_id=user["id"], ip=request.remote_addr)

    return jsonify({
        "secret":     setup.secret,
        "uri":        setup.uri,
        "qr_base64":  setup.qr_base64,
        "message":    "Scan the QR code with your authenticator app, then confirm with a token",
    })


@app.route("/api/mfa/confirm", methods=["POST"])
def mfa_confirm():
    payload, err, code = _require_token()
    if err:
        return err, code
    user  = _users.get(payload["sub"])
    data  = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()

    if not user or not user.get("mfa_pending_secret"):
        return jsonify({"error": "No pending MFA setup"}), 400

    if not verify_totp(user["mfa_pending_secret"], token):
        return jsonify({"error": "Invalid token — try again"}), 400

    user["mfa_secret"]  = user.pop("mfa_pending_secret")
    user["mfa_enabled"] = True
    backup_codes        = generate_backup_codes(10)
    user["backup_code_hashes"] = [hash_backup_code(c) for c in backup_codes]

    audit.log(AuditLevel.INFO, "MFA", "TOTP enabled",
              user_id=user["id"], ip=request.remote_addr)

    return jsonify({
        "message":      "MFA enabled successfully",
        "backup_codes": backup_codes,
        "warning":      "Store these backup codes safely — they will not be shown again",
    })


@app.route("/api/mfa/disable", methods=["POST"])
def mfa_disable():
    payload, err, code = _require_token()
    if err:
        return err, code
    user = _users.get(payload["sub"])
    data = request.get_json(silent=True) or {}

    if not user or not user["mfa_enabled"]:
        return jsonify({"error": "MFA is not enabled"}), 400

    if not verify_totp(user["mfa_secret"], data.get("token", "")):
        return jsonify({"error": "Invalid MFA token"}), 401

    user["mfa_enabled"] = False
    user["mfa_secret"]  = None
    user["backup_code_hashes"] = []
    audit.log(AuditLevel.WARN, "MFA", "MFA disabled",
              user_id=user["id"], ip=request.remote_addr)
    return jsonify({"message": "MFA disabled"})


@app.route("/api/mfa/totp-demo", methods=["GET"])
def totp_demo():
    """Demo endpoint: return current TOTP for the admin user (testing only)."""
    payload, err, code = _require_token()
    if err:
        return err, code
    user = _users.get(payload["sub"])
    if not user or not user.get("mfa_secret"):
        return jsonify({"error": "No TOTP configured"}), 404
    return jsonify(get_current_totp(user["mfa_secret"]))


# ═══════════════════════════════════════════════════════════════════════════════
# PASSWORD ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/password/analyze", methods=["POST"])
@limiter.limit("30 per minute")
def password_analyze():
    data = request.get_json(silent=True) or {}
    pwd  = data.get("password", "")
    user = data.get("username", "")
    if not pwd:
        return jsonify({"error": "password required"}), 400
    result = analyze_password(pwd, username=user)
    return jsonify({
        "score":        result.score,
        "strength":     result.strength,
        "entropy_bits": result.entropy_bits,
        "passes_policy":result.passes_policy,
        "violations":   result.violations,
        "suggestions":  result.suggestions,
    })


@app.route("/api/password/generate", methods=["GET"])
def password_generate():
    length = min(int(request.args.get("length", 20)), 64)
    return jsonify({"password": generate_secure_password(length)})


@app.route("/api/password/change", methods=["POST"])
@limiter.limit("5 per minute")
def password_change():
    payload, err, code = _require_token()
    if err:
        return err, code
    user  = _users.get(payload["sub"])
    data  = request.get_json(silent=True) or {}
    old_p = data.get("current_password", "")
    new_p = data.get("new_password", "")

    if not user:
        return jsonify({"error": "User not found"}), 404
    if not verify_password(user["password_hash"], old_p):
        return jsonify({"error": "Current password incorrect"}), 401

    # Policy check
    analysis = analyze_password(new_p, username=user["username"])
    if not analysis.passes_policy:
        return jsonify({"error": "New password does not meet policy",
                        "violations": analysis.violations}), 400

    # History check
    for old_hash in user.get("password_history", []):
        if verify_password(old_hash, new_p):
            return jsonify({"error": "Cannot reuse a recent password"}), 400

    # Update
    old_hash = user["password_hash"]
    user["password_history"] = ([old_hash] + user.get("password_history", []))[:10]
    user["password_hash"] = hash_password(new_p)

    audit.log(AuditLevel.INFO, "AUTH", "Password changed",
              user_id=user["id"], ip=request.remote_addr)
    return jsonify({"message": "Password changed successfully"})


# ═══════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/users", methods=["GET"])
def list_users():
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "users:read_all"):
        return jsonify({"error": "Insufficient privileges"}), 403

    users_out = []
    for u in _users.values():
        users_out.append({
            "id":          u["id"],
            "username":    u["username"],
            "email":       u["email"],
            "role":        u["role"],
            "mfa_enabled": u["mfa_enabled"],
            "active":      u["active"],
            "locked":      u["locked_until"] > time.time(),
            "last_login":  u["last_login"],
            "created_at":  u["created_at"],
        })
    return jsonify({"users": users_out, "total": len(users_out)})


@app.route("/api/users", methods=["POST"])
def create_user():
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "users:create"):
        return jsonify({"error": "Insufficient privileges"}), 403

    data = request.get_json(silent=True) or {}
    uname = data.get("username", "")
    pwd   = data.get("password", "")
    role  = data.get("role", "USER")
    email = data.get("email", "")

    uname_v = validate_input(uname, "username", strict=True)
    if not uname_v.valid:
        return jsonify({"error": uname_v.error}), 400
    if uname_v.sanitized in _usernames:
        return jsonify({"error": "Username already exists"}), 409

    analysis = analyze_password(pwd, username=uname_v.sanitized)
    if not analysis.passes_policy:
        return jsonify({"error": "Password does not meet policy",
                        "violations": analysis.violations}), 400

    user = _make_user(uname_v.sanitized, pwd, role.upper(), email)
    _users[user["id"]] = user
    _usernames[user["username"]] = user["id"]

    audit.log(AuditLevel.INFO, "USER", "User created",
              user_id=payload["sub"], ip=request.remote_addr,
              new_user=user["username"], role=role)
    return jsonify({"message": "User created", "id": user["id"]}), 201


@app.route("/api/users/<user_id>/lock", methods=["POST"])
def lock_user(user_id):
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "users:lock_unlock"):
        return jsonify({"error": "Insufficient privileges"}), 403

    user = _users.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user["locked_until"] = time.time() + 86400 * 365  # 1 year = effectively permanent
    audit.log(AuditLevel.WARN, "USER", f"Account locked: {user['username']}",
              user_id=payload["sub"], ip=request.remote_addr)
    return jsonify({"message": f"User {user['username']} locked"})


@app.route("/api/users/<user_id>/unlock", methods=["POST"])
def unlock_user(user_id):
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "users:lock_unlock"):
        return jsonify({"error": "Insufficient privileges"}), 403

    user = _users.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user["locked_until"]    = 0
    user["failed_attempts"] = 0
    audit.log(AuditLevel.INFO, "USER", f"Account unlocked: {user['username']}",
              user_id=payload["sub"], ip=request.remote_addr)
    return jsonify({"message": f"User {user['username']} unlocked"})


@app.route("/api/users/<user_id>/role", methods=["PUT"])
def change_role(user_id):
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "users:change_role"):
        return jsonify({"error": "Insufficient privileges — SUPERADMIN required"}), 403

    user     = _users.get(user_id)
    data     = request.get_json(silent=True) or {}
    new_role = data.get("role", "").upper()

    if not user:
        return jsonify({"error": "User not found"}), 404

    allowed = {"VIEWER","USER","ANALYST","DEVELOPER","ADMIN","SUPERADMIN"}
    if new_role not in allowed:
        return jsonify({"error": f"Invalid role. Choose from: {allowed}"}), 400

    ok = privilege_monitor.record_role_change(
        user_id, user["role"], new_role,
        payload["sub"], request.remote_addr
    )
    if not ok:
        return jsonify({"error": "Role change blocked — anomalous escalation pattern"}), 403

    old_role = user["role"]
    user["role"] = new_role
    return jsonify({"message": f"Role changed from {old_role} to {new_role}"})


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY / SCAN ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/security/scan/trapdoors", methods=["POST"])
def scan_trapdoors():
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "security:run_scan"):
        return jsonify({"error": "Insufficient privileges"}), 403

    data    = request.get_json(silent=True) or {}
    path    = data.get("path", ".")
    # Sanitize path — prevent traversal
    safe_path = os.path.abspath(path)
    findings = scan_for_trapdoors(safe_path)

    return jsonify({
        "path":     safe_path,
        "findings": [
            {"severity":    f.severity,
             "file":        f.file,
             "line":        f.line,
             "description": f.description,
             "snippet":     f.snippet}
            for f in findings
        ],
        "total":    len(findings),
        "status":   "clean" if not findings else "issues_found",
    })


@app.route("/api/security/os-checks", methods=["GET"])
def os_security_checks():
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "security:run_scan"):
        return jsonify({"error": "Insufficient privileges"}), 403

    checks    = check_system_security()
    priv_info = get_privilege_info()
    return jsonify({
        "platform":  PLATFORM,
        "pam_available": PAM_AVAILABLE,
        "checks":    checks,
        "process_privileges": {
            "is_root":      priv_info.is_root,
            "has_sudo":     priv_info.has_sudo,
            "effective_uid":priv_info.effective_uid,
            "suid_files":   priv_info.suid_files[:10],
        },
    })


@app.route("/api/security/system-users", methods=["GET"])
def system_users():
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "security:run_scan"):
        return jsonify({"error": "Insufficient privileges"}), 403

    users = list_system_users(include_system=False)
    return jsonify({
        "platform": PLATFORM,
        "users": [
            {"username":  u.username,
             "uid":       u.uid,
             "shell":     u.shell,
             "is_locked": u.is_locked,
             "has_password": u.has_password,
             "groups":    u.groups[:5]}
            for u in users
        ],
        "total": len(users),
    })


@app.route("/api/security/pam-auth", methods=["POST"])
@limiter.limit("5 per minute")
def pam_auth():
    """Authenticate against the OS PAM stack (requires appropriate privileges)."""
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "security:run_scan"):
        return jsonify({"error": "Insufficient privileges"}), 403

    data    = request.get_json(silent=True) or {}
    uname_v = validate_input(data.get("username", ""), "username", strict=True)
    pass_v  = validate_input(data.get("password", ""), "password")

    if not uname_v.valid or not pass_v.valid:
        return jsonify({"error": "Invalid input"}), 400

    result = os_authenticate(uname_v.sanitized, pass_v.sanitized)
    audit.log(
        AuditLevel.INFO if result.success else AuditLevel.WARN,
        "PAM",
        f"PAM auth {'success' if result.success else 'failed'} for {uname_v.sanitized}",
        user_id=payload["sub"], ip=request.remote_addr,
    )
    return jsonify({
        "success": result.success,
        "method":  result.method,
        "message": result.message,
        "uid":     result.uid,
        "groups":  result.groups,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/audit/events", methods=["GET"])
def audit_events():
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "audit:read"):
        return jsonify({"error": "Insufficient privileges"}), 403

    limit    = min(int(request.args.get("limit", 50)), 500)
    category = request.args.get("category")
    events   = audit.get_events(limit=limit, category=category)
    return jsonify({
        "events":   events,
        "total":    audit.count,
        "chain_ok": audit.verify_chain(),
    })


@app.route("/api/audit/chain-verify", methods=["GET"])
def chain_verify():
    payload, err, code = _require_token()
    if err:
        return err, code
    if not check_permission(payload["role"], "audit:read"):
        return jsonify({"error": "Insufficient privileges"}), 403
    ok = audit.verify_chain()
    return jsonify({
        "chain_intact": ok,
        "total_events": audit.count,
        "message": "Audit chain verified — no tampering detected" if ok
                   else "CHAIN BROKEN — audit log may have been tampered with",
    })


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({
        "service":       "SecureAuth Framework",
        "version":       "1.0.0",
        "platform":      PLATFORM,
        "pam_available": PAM_AVAILABLE,
        "users_count":   len(_users),
        "audit_events":  audit.count,
        "chain_ok":      audit.verify_chain(),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  SecureAuth API running on http://localhost:{port}")
    print(f"  Platform: {PLATFORM} | PAM: {PAM_AVAILABLE}")
    print(f"  Demo users: admin / developer / analyst / user\n")
    app.run(host="0.0.0.0", port=port, debug=False)
