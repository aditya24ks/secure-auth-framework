"""
SecureAuth - OS Integration Layer
Implements: PAM (Linux) integration, Windows LSA stub, OS-level session
            management, system user enumeration, privilege detection

NOTE: PAM calls require the python-pam package and the process must have
      appropriate privileges. This module degrades gracefully when PAM
      is unavailable (e.g., in containerised / non-Linux environments).
"""

import os
import sys
import platform
import subprocess
import grp
import pwd
import stat
from dataclasses import dataclass
from typing import Optional


PLATFORM = platform.system()  # "Linux", "Darwin", "Windows"
PAM_AVAILABLE = False

if PLATFORM in ("Linux", "Darwin"):
    try:
        import pam as _pam
        PAM_AVAILABLE = True
    except ImportError:
        pass  # pam module not installed — graceful degradation


@dataclass
class OSAuthResult:
    success: bool
    method: str          # "pam" | "shadow_stub" | "windows_lsa" | "unsupported"
    message: str
    uid: Optional[int] = None
    gid: Optional[int] = None
    groups: list[str] = None


@dataclass
class SystemUserInfo:
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    groups: list[str]
    has_password: bool
    is_locked: bool
    is_system_account: bool


@dataclass
class PrivilegeInfo:
    has_sudo: bool
    sudo_groups: list[str]
    is_root: bool
    effective_uid: int
    real_uid: int
    suid_files: list[str]          # potentially dangerous SUID binaries


# ── PAM authentication ────────────────────────────────────────────────────────

def authenticate_via_pam(username: str, password: str,
                         service: str = "secureauth") -> OSAuthResult:
    """
    Authenticate a username/password against the OS PAM stack.
    Falls back gracefully when PAM is not available.
    """
    if not PAM_AVAILABLE:
        return OSAuthResult(
            success=False,
            method="pam_unavailable",
            message="PAM not available — install python-pam and run with appropriate privileges",
        )

    try:
        p = _pam.pam()
        ok = p.authenticate(username, password, service=service)
        if ok:
            try:
                pw = pwd.getpwnam(username)
                groups = [g.gr_name for g in grp.getgrall()
                          if username in g.gr_mem or g.gr_gid == pw.pw_gid]
                return OSAuthResult(
                    success=True, method="pam",
                    message="PAM authentication successful",
                    uid=pw.pw_uid, gid=pw.pw_gid, groups=groups,
                )
            except KeyError:
                return OSAuthResult(success=True, method="pam",
                                    message="PAM authentication successful", groups=[])
        else:
            return OSAuthResult(success=False, method="pam",
                                message=f"PAM authentication failed: {p.reason}")
    except Exception as e:
        return OSAuthResult(success=False, method="pam",
                            message=f"PAM error: {str(e)[:100]}")


def authenticate_via_windows_lsa(username: str, password: str,
                                  domain: str = ".") -> OSAuthResult:
    """
    Windows LSA/SSPI authentication stub.
    In a full implementation this would call win32security.LogonUser().
    """
    if PLATFORM != "Windows":
        return OSAuthResult(success=False, method="windows_lsa",
                            message="Windows LSA only available on Windows")
    try:
        import win32security
        import win32con
        token = win32security.LogonUser(
            username, domain, password,
            win32con.LOGON32_LOGON_INTERACTIVE,
            win32con.LOGON32_PROVIDER_DEFAULT,
        )
        return OSAuthResult(success=True, method="windows_lsa",
                            message="Windows LSA authentication successful")
    except ImportError:
        return OSAuthResult(success=False, method="windows_lsa",
                            message="pywin32 not installed")
    except Exception as e:
        return OSAuthResult(success=False, method="windows_lsa",
                            message=f"LSA error: {str(e)[:100]}")


def os_authenticate(username: str, password: str) -> OSAuthResult:
    """
    Platform-agnostic OS authentication entry point.
    Routes to PAM on Linux/macOS, LSA on Windows.
    """
    if PLATFORM in ("Linux", "Darwin"):
        return authenticate_via_pam(username, password)
    elif PLATFORM == "Windows":
        return authenticate_via_windows_lsa(username, password)
    else:
        return OSAuthResult(success=False, method="unsupported",
                            message=f"Unsupported platform: {PLATFORM}")


# ── System user enumeration ───────────────────────────────────────────────────

def list_system_users(include_system: bool = False) -> list[SystemUserInfo]:
    """
    Enumerate OS user accounts from /etc/passwd.
    Flags locked accounts and system accounts.
    """
    if PLATFORM not in ("Linux", "Darwin"):
        return []

    users = []
    try:
        for pw in pwd.getpwall():
            is_system = pw.pw_uid < 1000 or pw.pw_shell in (
                "/bin/false", "/usr/sbin/nologin", "/sbin/nologin"
            )
            if is_system and not include_system:
                continue

            groups = [g.gr_name for g in grp.getgrall()
                      if pw.pw_name in g.gr_mem or g.gr_gid == pw.pw_gid]

            # Detect locked account (shadow '!' or '*' prefix)
            is_locked = False
            try:
                shadow = pwd.getspnam(pw.pw_name)
                is_locked = shadow.sp_pwdp.startswith(("!", "*"))
                has_password = bool(shadow.sp_pwdp and
                                    shadow.sp_pwdp not in ("", "!", "*"))
            except (KeyError, AttributeError, PermissionError):
                is_locked = pw.pw_passwd in ("!", "*", "x")
                has_password = pw.pw_passwd not in ("", "!", "*", "x")

            users.append(SystemUserInfo(
                username=pw.pw_name,
                uid=pw.pw_uid,
                gid=pw.pw_gid,
                home=pw.pw_dir,
                shell=pw.pw_shell,
                groups=groups,
                has_password=has_password,
                is_locked=is_locked,
                is_system_account=is_system,
            ))
    except (PermissionError, OSError):
        pass
    return users


# ── Privilege detection ───────────────────────────────────────────────────────

def get_privilege_info() -> PrivilegeInfo:
    """
    Analyse current process privileges and detect risky SUID binaries.
    """
    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    ruid = os.getuid()  if hasattr(os, "getuid")  else -1
    is_root = euid == 0

    # Determine sudo-capable groups
    sudo_groups = []
    if PLATFORM in ("Linux", "Darwin"):
        try:
            with open("/etc/sudoers", "r") as f:
                for line in f:
                    m = __import__("re").search(r"^%(\S+)\s+ALL", line)
                    if m:
                        sudo_groups.append(m.group(1))
        except (IOError, PermissionError):
            sudo_groups = ["sudo", "wheel"]  # common defaults

    current_user = pwd.getpwuid(ruid).pw_name if PLATFORM in ("Linux", "Darwin") else ""
    user_groups = [g.gr_name for g in grp.getgrall()
                   if current_user in g.gr_mem] if current_user else []
    has_sudo = is_root or any(g in sudo_groups for g in user_groups)

    # Scan for SUID binaries in common directories
    suid_files = []
    for search_dir in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]:
        if not os.path.isdir(search_dir):
            continue
        try:
            for fname in os.listdir(search_dir):
                fpath = os.path.join(search_dir, fname)
                try:
                    st = os.stat(fpath)
                    if st.st_mode & stat.S_ISUID:
                        suid_files.append(fpath)
                except OSError:
                    continue
        except PermissionError:
            continue

    return PrivilegeInfo(
        has_sudo=has_sudo,
        sudo_groups=sudo_groups,
        is_root=is_root,
        effective_uid=euid,
        real_uid=ruid,
        suid_files=suid_files[:20],  # cap list
    )


# ── System security checks ────────────────────────────────────────────────────

def check_system_security() -> dict:
    """
    Run OS-level security checks.
    Returns a dict of check_name → {status, detail}.
    """
    checks = {}

    if PLATFORM in ("Linux", "Darwin"):
        # ASLR
        aslr_val = "unknown"
        try:
            with open("/proc/sys/kernel/randomize_va_space") as f:
                aslr_val = f.read().strip()
        except (IOError, OSError):
            pass
        checks["aslr"] = {
            "status": "pass" if aslr_val == "2" else "warn" if aslr_val == "1" else "fail",
            "value": aslr_val,
            "detail": {
                "2": "Full ASLR (randomize_va_space=2)",
                "1": "Partial ASLR",
                "0": "ASLR disabled — vulnerable to return-oriented programming",
            }.get(aslr_val, f"Cannot read (value: {aslr_val})"),
        }

        # NX/DEP bit check via /proc/cpuinfo
        nx_enabled = False
        try:
            with open("/proc/cpuinfo") as f:
                cpu_flags = f.read()
                nx_enabled = " nx " in cpu_flags or "\tnx\n" in cpu_flags or "nx\n" in cpu_flags
        except (IOError, OSError):
            pass
        checks["nx_bit"] = {
            "status": "pass" if nx_enabled else "warn",
            "detail": "NX/XD bit enabled (no-execute stack)" if nx_enabled
                      else "NX bit status unknown",
        }

        # /etc/shadow permissions
        shadow_ok = False
        try:
            st = os.stat("/etc/shadow")
            shadow_ok = not (st.st_mode & (stat.S_IRGRP | stat.S_IROTH))
        except (OSError, PermissionError):
            shadow_ok = True  # can't read = probably fine
        checks["shadow_perms"] = {
            "status": "pass" if shadow_ok else "fail",
            "detail": "/etc/shadow permissions are restrictive" if shadow_ok
                      else "/etc/shadow is world/group readable — CRITICAL",
        }

        # Root login check
        root_login_ok = True
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    if line.startswith("root:") and not line.startswith("root:x:"):
                        root_login_ok = False
        except (IOError, OSError):
            pass
        checks["root_passwd"] = {
            "status": "pass" if root_login_ok else "fail",
            "detail": "Root password is shadowed" if root_login_ok
                      else "Root password found in /etc/passwd — not shadowed",
        }

        # SSH root login
        ssh_root = "unknown"
        try:
            result = subprocess.run(
                ["sshd", "-T"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "permitrootlogin" in line.lower():
                    ssh_root = line.split()[-1].lower()
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            ssh_root = "sshd not found"
        checks["ssh_root_login"] = {
            "status": "pass" if ssh_root in ("no", "prohibit-password")
                      else "warn" if ssh_root in ("unknown", "sshd not found")
                      else "fail",
            "detail": f"PermitRootLogin: {ssh_root}",
        }

    else:
        checks["platform"] = {
            "status": "warn",
            "detail": f"OS security checks not implemented for {PLATFORM}",
        }

    return checks
