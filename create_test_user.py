import os
os.environ.setdefault("DATABASE_URL", "")
from backend.app.database import init_db, get_db
from backend.app.security import create_access_token, hash_password

init_db()
with get_db() as conn:
    pw = hash_password("password123")
    cur = conn.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", ("test@example.com", pw, "ADMIN"))
    user_id = cur.lastrowid
    token = create_access_token(str(user_id))
    print("USER_ID:", user_id)
    print("TOKEN:", token)
