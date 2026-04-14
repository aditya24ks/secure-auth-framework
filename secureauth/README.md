# SecureAuth Framework

A robust authentication framework integrating with existing operating systems.

## Quick Start
```bash
pip install -r requirements.txt
python run.py          # API + dashboard on :5001
python tests/test_suite.py
python cli.py password generate --length 24
python cli.py mfa setup alice@company.com
python cli.py scan os
python cli.py hash benchmark
```

## Demo Credentials
- admin / Admin@SecureAuth1!
- developer / Dev@SecurePass9#
- analyst / Analyst$Pass7^
- user / User@Pass5&Simple

## Architecture
- core/password_manager.py  Argon2id + pepper + timing-safe verify
- core/mfa.py               RFC 6238 TOTP, backup codes, JWT, rate limiter
- core/security.py          RBAC, tamper-evident audit chain, trapdoor scanner
- core/os_integration.py    PAM/LSA, ASLR/NX checks, SUID scan
- core/database.py          SQLite persistence layer
- api/server.py             22-endpoint Flask REST API
- static/index.html         Admin dashboard
- tests/test_suite.py       83/84 tests pass
- cli.py                    CLI admin tool
