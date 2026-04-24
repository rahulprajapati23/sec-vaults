import sqlite3

conn = sqlite3.connect("./data/app.db")
cursor = conn.cursor()

# Clear all tables
tables_to_clear = ["users", "otp_tokens", "email_verifications", "files", "user_sessions"]

for table in tables_to_clear:
    try:
        cursor.execute(f"DELETE FROM {table}")
        count = cursor.rowcount
        print(f"✓ Cleared {table}: {count} rows deleted")
    except sqlite3.OperationalError as e:
        print(f"✗ {table}: {e}")

conn.commit()
conn.close()

print("\n✅ All test data cleared!")
