import os
import sys
from pathlib import Path

# Add the current directory to sys.path so we can import backend
sys.path.append(os.getcwd())

from backend.app.database import get_db

def promote():
    try:
        print("Connecting to database...")
        # Using context manager as intended in database.py
        with get_db() as conn:
            email = 'rahul2100007@gmail.com'
            # First check if user exists
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            
            if not user:
                print(f"User {email} not found. Please register first on the website.")
                return

            print(f"Found user: {user['email']} with current role: {user['role']}")
            
            # Update role to ADMIN
            conn.execute("UPDATE users SET role = 'ADMIN' WHERE email = ?", (email,))
            print(f"SUCCESS: {email} has been promoted to ADMIN.")
        
        print("Please restart your backend and frontend (if needed), then log in again.")
        
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    promote()
