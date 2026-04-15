#!/usr/bin/env python3
"""
SecureAuth CLI — command-line administration tool
Commands: user, password, mfa, scan, audit, hash
"""
import sys, os, time, argparse, getpass
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

def c(text, colour):
    codes = {'green':'\033[32m','red':'\033[31m','yellow':'\033[33m',
             'cyan':'\033[36m','bold':'\033[1m','reset':'\033[0m','dim':'\033[2m'}
    return f"{codes.get(colour,'')}{text}{codes['reset']}"

def ok(msg):   print(c('  ✓ ', 'green')  + msg)
def err(msg):  print(c('  ✗ ', 'red')    + msg)
def warn(msg): print(c('  ⚠ ', 'yellow') + msg)
def info(msg): print(c('  · ', 'cyan')   + msg)
def head(msg): print(c(f'\n  {msg}', 'bold'))
def sep():     print(c('  ' + '─' * 52, 'dim'))

def cmd_password_analyze(args):
    from core.password_manager import analyze_password
    password = args.password or getpass.getpass('  Password to analyze: ')
    head('Password Analysis')
    sep()
    a = analyze_password(password, username=getattr(args,'username','') or '')
    bars   = '█' * (a.score // 10) + '░' * (10 - a.score // 10)
    colour = 'green' if a.score >= 80 else 'yellow' if a.score >= 50 else 'red'
    labels = {'very_weak':'VERY WEAK','weak':'WEAK','fair':'FAIR','strong':'STRONG','very_strong':'VERY STRONG'}
    print(f"\n  Score:    {c(str(a.score)+'/100', colour)}  [{c(bars, colour)}]")
    print(f"  Strength: {c(labels.get(a.strength, a.strength), colour)}")
    print(f"  Entropy:  {a.entropy_bits} bits")
    print(f"  Policy:   {'PASS ✓' if a.passes_policy else 'FAIL ✗'}")
    if a.violations:
        print(); warn('Violations:')
        for v in a.violations: print(f'    {c("✗","red")} {v}')
    if a.suggestions:
        print(); info('Suggestions:')
        for s in a.suggestions: print(f'    → {s}')
    sep()
    return 0

def cmd_password_generate(args):
    from core.password_manager import generate_secure_password, analyze_password
    length = int(getattr(args,'length',20) or 20)
    head(f'Generate Secure Password (length={length})')
    pwd = generate_secure_password(length)
    a   = analyze_password(pwd)
    print(f'\n  {c(pwd,"cyan")}\n')
    info(f'Score: {a.score}/100  Entropy: {a.entropy_bits} bits  Strength: {a.strength}')
    return 0

def cmd_mfa_setup(args):
    from core.mfa import generate_totp_setup, get_current_totp, generate_backup_codes, hash_backup_code
    head(f'TOTP MFA Setup for {args.username}')
    setup = generate_totp_setup(args.username)
    sep()
    print(f'\n  {c("Secret (base32):","bold")} {setup.secret}')
    print(f'  {c("URI:","bold")}           {setup.uri[:72]}')
    print(f'  {c("QR PNG:","bold")}        {len(setup.qr_base64)} bytes (base64)')
    codes = generate_backup_codes(10)
    print(f'\n  {c("Backup codes (shown once):","bold")}')
    for i,code in enumerate(codes,1): print(f'    {i:>2}. {c(code,"yellow")}')
    current = get_current_totp(setup.secret)
    print(f'\n  {c("Current token:","bold")} {c(current["token"],"green")} (valid {current["remaining_seconds"]}s)')
    sep()
    return 0

def cmd_mfa_verify(args):
    from core.mfa import verify_totp
    head('MFA Token Verification')
    token  = getattr(args,'token','')  or input('  Token: ').strip()
    secret = getattr(args,'secret','') or input('  Secret: ').strip()
    result = verify_totp(secret, token)
    (ok if result else err)(f'Token {c(token,"cyan")} is {"VALID" if result else "INVALID"}')
    return 0 if result else 1

def cmd_scan_trapdoors(args):
    from core.security import scan_for_trapdoors
    path = getattr(args,'path','.') or '.'
    head(f'Trapdoor Scanner — {os.path.abspath(path)}')
    sep(); info('Scanning…')
    findings = scan_for_trapdoors(path)
    if not findings:
        ok('No trapdoor signatures found')
    else:
        sev_c = {'CRITICAL':'red','HIGH':'red','MEDIUM':'yellow','LOW':'dim'}
        print()
        for f in findings:
            print(f'  {c(f.severity, sev_c.get(f.severity,"dim")):<18} {f.file}:{f.line}')
            print(f'  {c("Pattern:","dim")} {f.description}')
            print(f'  {c("Snippet:","dim")} {f.snippet[:80]}\n')
        err(f'{len(findings)} finding(s)')
    sep(); return 0

def cmd_scan_os(args):
    from core.os_integration import check_system_security, get_privilege_info, list_system_users, PLATFORM, PAM_AVAILABLE
    head(f'OS Security Scan — {PLATFORM}')
    sep()
    checks = check_system_security()
    icons  = {'pass':c('PASS','green'),'warn':c('WARN','yellow'),'fail':c('FAIL','red')}
    for name, result in checks.items():
        print(f"  {name:<22} {icons.get(result['status'], result['status']):<18} {c(result.get('detail',''),'dim')}")
    sep()
    priv = get_privilege_info()
    head('Process Privileges')
    info(f'Platform: {PLATFORM} | PAM: {PAM_AVAILABLE}')
    info(f'Effective UID: {priv.effective_uid} | Is root: {c(str(priv.is_root),"red" if priv.is_root else "green")}')
    info(f'Has sudo: {priv.has_sudo} | SUID binaries: {len(priv.suid_files)}')
    sep()
    users = list_system_users()
    head(f'OS Users ({len(users)} non-system)')
    for u in users[:10]:
        locked = c('[LOCKED]','red') if u.is_locked else ''
        nopwd  = c('[NO PWD]','yellow') if not u.has_password else ''
        print(f'  {u.username:<20} uid={u.uid:<6} {u.shell:<26} {locked}{nopwd}')
    sep(); return 0

def cmd_audit_show(args):
    from core.security import audit, AuditLevel
    audit.log(AuditLevel.INFO, 'AUDIT', 'CLI audit view')
    limit    = int(getattr(args,'limit',20) or 20)
    category = getattr(args,'category',None)
    events   = audit.get_events(limit=limit, category=category)
    head(f'Audit Log — {limit} events' + (f' [{category}]' if category else ''))
    sep()
    lc = {'INFO':'cyan','WARN':'yellow','FAIL':'red','CRIT':'red'}
    for e in events:
        ts  = e['timestamp'].split('T')[1][:8]
        lv  = c(f"[{e['level']:<4}]", lc.get(e['level'],'dim'))
        cat = c(f"[{e['category']:<9}]", 'dim')
        uid = c(e.get('user_id') or 'system', 'cyan')
        print(f"  {ts}  {lv} {cat}  {e['message'][:50]:<52} {uid}")
    sep(); info(f'Total: {audit.count} events | Chain: {"OK" if audit.verify_chain() else "BROKEN"}')
    return 0

def cmd_audit_chain(args):
    from core.security import audit, AuditLevel
    head('Audit Chain Integrity')
    sep()
    audit.log(AuditLevel.INFO, 'AUDIT', 'Chain verification via CLI')
    flag = audit.verify_chain()
    (ok if flag else err)(f'Chain {"INTACT" if flag else "BROKEN"} — {audit.count} events')
    sep(); return 0 if flag else 1

def cmd_hash_benchmark(args):
    from core.password_manager import hash_password, verify_password
    head('Argon2id Benchmark')
    sep()
    pwd = 'BenchmarkPassword@123!'
    hash_times, verify_times = [], []
    for i in range(3):
        t0 = time.perf_counter(); h = hash_password(pwd)
        hash_times.append(time.perf_counter() - t0)
        info(f'Hash {i+1}: {hash_times[-1]*1000:.1f} ms')
    for i in range(3):
        t0 = time.perf_counter(); verify_password(h, pwd)
        verify_times.append(time.perf_counter() - t0)
        info(f'Verify {i+1}: {verify_times[-1]*1000:.1f} ms')
    avg_h = sum(hash_times)/len(hash_times)
    avg_v = sum(verify_times)/len(verify_times)
    sep()
    print(f'  Avg hash:   {c(f"{avg_h*1000:.1f} ms","cyan")}')
    print(f'  Avg verify: {c(f"{avg_v*1000:.1f} ms","cyan")}')
    print(f'  Throughput: {c(f"{1/avg_h:.2f} hashes/sec","yellow")} per CPU core')
    info('Memory-hard (64MB) makes GPU/ASIC attacks ~2000x slower vs bcrypt')
    sep(); return 0

def cmd_user_create(args):
    from core.password_manager import analyze_password, hash_password
    from core.security import validate_input, audit, AuditLevel
    head('Create User')
    uv = validate_input(args.username, 'username', strict=True)
    if not uv.valid: err(f'Invalid username: {uv.error}'); return 1
    password = getattr(args,'password',None) or getpass.getpass('  Password: ')
    a = analyze_password(password, username=args.username)
    if not a.passes_policy:
        err('Password fails policy:')
        for v in a.violations: print(f'    - {v}')
        return 1
    role = (getattr(args,'role','USER') or 'USER').upper()
    ph   = hash_password(password)
    audit.log(AuditLevel.INFO,'USER',f'CLI: user created {args.username}',details={'role':role})
    ok(f'User {c(args.username,"cyan")} created | role={c(role,"yellow")} | score={a.score}')
    info(f'Hash: {ph[:42]}…')
    return 0

DISPATCH = {
    ('password','analyze'):      cmd_password_analyze,
    ('password','generate'):     cmd_password_generate,
    ('mfa','setup'):             cmd_mfa_setup,
    ('mfa','verify'):            cmd_mfa_verify,
    ('scan','trapdoors'):        cmd_scan_trapdoors,
    ('scan','os'):               cmd_scan_os,
    ('audit','show'):            cmd_audit_show,
    ('audit','verify-chain'):    cmd_audit_chain,
    ('hash','benchmark'):        cmd_hash_benchmark,
    ('user','create'):           cmd_user_create,
}

def build_parser():
    p = argparse.ArgumentParser(prog='secureauth', description='SecureAuth CLI')
    sub = p.add_subparsers(dest='cmd')
    usr = sub.add_parser('user'); us = usr.add_subparsers(dest='subcmd')
    uc = us.add_parser('create'); uc.add_argument('username'); uc.add_argument('password',nargs='?'); uc.add_argument('--role',default='USER')
    pw = sub.add_parser('password'); ps = pw.add_subparsers(dest='subcmd')
    pa = ps.add_parser('analyze'); pa.add_argument('password',nargs='?'); pa.add_argument('--username',default='')
    pg = ps.add_parser('generate'); pg.add_argument('--length',default=20,type=int)
    mf = sub.add_parser('mfa'); ms = mf.add_subparsers(dest='subcmd')
    ms2 = ms.add_parser('setup'); ms2.add_argument('username')
    mv = ms.add_parser('verify'); mv.add_argument('token',nargs='?',default=''); mv.add_argument('--secret',default='')
    sc = sub.add_parser('scan'); ss = sc.add_subparsers(dest='subcmd')
    st = ss.add_parser('trapdoors'); st.add_argument('--path',default='.')
    ss.add_parser('os')
    au = sub.add_parser('audit'); aus = au.add_subparsers(dest='subcmd')
    as_ = aus.add_parser('show'); as_.add_argument('--limit',default=20,type=int); as_.add_argument('--category',default=None)
    aus.add_parser('verify-chain')
    hb = sub.add_parser('hash'); hbs = hb.add_subparsers(dest='subcmd'); hbs.add_parser('benchmark')
    return p

def main():
    parser = build_parser()
    args   = parser.parse_args()
    print(c('\n  ┌─────────────────────────────────┐','dim'))
    print(c('  │  SecureAuth Framework CLI v1.0  │','cyan'))
    print(c('  └─────────────────────────────────┘','dim'))
    key = (args.cmd, getattr(args,'subcmd',None))
    fn  = DISPATCH.get(key)
    if not fn: parser.print_help(); return 1
    return fn(args) or 0

if __name__ == '__main__':
    sys.exit(main())
