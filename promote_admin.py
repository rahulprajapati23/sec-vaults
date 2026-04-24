import sqlite3
from pathlib import Path
from app.config import get_settings

def promote_user():
    db_path = get_settings().database_path
    if not db_path.exists():
        print("Database not found!")
        return

    with sqlite3.connect(db_path) as conn:
        # Give the current user admin role
        conn.execute("UPDATE users SET role = 'admin' WHERE email = 'rahul2100007@gmail.com'")
        conn.commit()
        print("Successfully promoted rahul2100007@gmail.com to admin!")

if __name__ == "__main__":
    promote_user()
