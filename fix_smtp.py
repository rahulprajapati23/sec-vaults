import os
import sys
from pathlib import Path

# Add the current directory to sys.path
sys.path.append(os.getcwd())

from backend.app.database import get_db

def fix_smtp():
    try:
        print("Updating SMTP settings in database...")
        with get_db() as conn:
            # Set email_provider to smtp and enable it
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('email_provider', 'smtp')")
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('smtp_enabled', 'true')")
            conn.commit()
            print("SUCCESS: System is now configured to use SMTP (Gmail).")
            print("Please restart your backend server now.")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    fix_smtp()
