"""
Standalone SMTP diagnostic + fix script.
Run: python test_smtp.py
"""
import os
import sys
import smtplib
from pathlib import Path

# Load .env manually
env_path = Path(__file__).parent / ".env"
env = {}
for line in env_path.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, val = line.split("=", 1)
    env[key.strip()] = val.strip().strip('"').strip("'")

print("=" * 60)
print("SMTP DIAGNOSTIC REPORT")
print("=" * 60)

smtp_enabled = env.get("SMTP_ENABLED", "false").lower()
smtp_host    = env.get("SMTP_HOST", "")
smtp_port    = int(env.get("SMTP_PORT", "587"))
smtp_user    = env.get("SMTP_USER", "")
smtp_pass    = env.get("SMTP_PASSWORD", "")
smtp_sender  = env.get("SMTP_SENDER", "")
smtp_tls     = env.get("SMTP_STARTTLS", "true").lower()

print(f"SMTP_ENABLED    : {smtp_enabled}")
print(f"SMTP_HOST       : {smtp_host}")
print(f"SMTP_PORT       : {smtp_port}")
print(f"SMTP_USER       : {smtp_user}")
print(f"SMTP_PASSWORD   : {repr(smtp_pass)}  (length={len(smtp_pass)})")
print(f"SMTP_SENDER     : {smtp_sender}")
print(f"SMTP_STARTTLS   : {smtp_tls}")
print()

if smtp_enabled not in ("true", "1", "yes"):
    print("❌ SMTP_ENABLED is not 'true'. Fix: set SMTP_ENABLED=true in .env")
    sys.exit(1)

if not smtp_host:
    print("❌ SMTP_HOST is empty")
    sys.exit(1)

if not smtp_user:
    print("❌ SMTP_USER is empty")
    sys.exit(1)

if not smtp_pass:
    print("❌ SMTP_PASSWORD is empty")
    sys.exit(1)

# Check for spaces in password (Gmail App Password issue)
if " " in smtp_pass:
    clean = smtp_pass.replace(" ", "")
    print(f"⚠️  SMTP_PASSWORD has spaces. Gmail App Passwords should NOT have spaces.")
    print(f"   Current : {repr(smtp_pass)}")
    print(f"   Fixed   : {repr(clean)}")
    print()
    # Auto-fix .env
    content = env_path.read_text(encoding="utf-8")
    content = content.replace(
        f"SMTP_PASSWORD={smtp_pass}",
        f"SMTP_PASSWORD={clean}"
    )
    env_path.write_text(content, encoding="utf-8")
    smtp_pass = clean
    print("✅ Auto-fixed SMTP_PASSWORD in .env (removed spaces)")
    print()

print("🔌 Testing SMTP connection...")
try:
    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
        server.ehlo()
        if smtp_tls in ("true", "1", "yes"):
            server.starttls()
            server.ehlo()
        print(f"✅ Connected to {smtp_host}:{smtp_port} OK")
        server.login(smtp_user, smtp_pass)
        print(f"✅ Login as {smtp_user} succeeded")

    print()
    print("=" * 60)
    print("✅ SMTP IS WORKING! Restart the backend to apply .env changes.")
    print("=" * 60)

except smtplib.SMTPAuthenticationError as e:
    print(f"❌ Authentication failed: {e}")
    print()
    print("POSSIBLE FIXES:")
    print("1. Use Gmail App Password (not your real Gmail password)")
    print("   → Go to: https://myaccount.google.com/apppasswords")
    print("   → Generate an app password for 'Mail'")
    print("   → Paste it WITHOUT spaces into SMTP_PASSWORD in .env")
    print("2. Enable 2-Step Verification on your Google account first")
    print("3. Make sure SMTP_USER matches the Gmail account")
except smtplib.SMTPConnectError as e:
    print(f"❌ Cannot connect to {smtp_host}:{smtp_port}: {e}")
    print("Check SMTP_HOST and SMTP_PORT in .env")
except Exception as e:
    print(f"❌ Unexpected error: {type(e).__name__}: {e}")
