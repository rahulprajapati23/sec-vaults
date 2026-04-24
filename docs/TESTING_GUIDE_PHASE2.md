# DAM System Phase 2 - Quick Start Testing Guide

## Environment Setup

### 1. Verify Configuration

Check that `.env` has new settings:

```bash
GEOLOCATION_ENABLED=true
EMAIL_VERIFICATION_ENABLED=true
MFA_ENABLED=true
MFA_EXPIRY_MINUTES=5
TELEGRAM_ENABLED=false          # Set to true if you have bot token
TELEGRAM_BOT_TOKEN=             # Get from @BotFather
TELEGRAM_CHAT_IDS=              # Your telegram chat ID
LOG_RETENTION_DAYS=90
SESSION_MAX_AGE_HOURS=24
```

### 2. Start Application

```bash
cd d:\DSSPrjct
.\.venv\Scripts\activate
python -m uvicorn app.main:app --reload
```

App runs at: `http://127.0.0.1:8000`

---

## Feature Testing

### Feature 1: Email Verification

**Test Flow:**

1. **Register new account:**
   ```
   GET http://127.0.0.1:8000/auth/register
   Form: email=test@example.com, password=SecurePass123
   ```
   
2. **Request verification email (after login):**
   ```
   POST http://127.0.0.1:8000/auth/verify-email-request
   Headers: Cookie: access_token=<your_token>
   ```
   
3. **Check console or logs for verification link:**
   - Email printed to logs (SMTP in dev mode)
   - Example: `http://127.0.0.1:8000/auth/verify-email?token=abc123def456`
   
4. **Click verification link:**
   ```
   GET http://127.0.0.1:8000/auth/verify-email?token=<token_from_email>
   ```
   - Success: "Email verified successfully" message
   - Failure: "Invalid or expired token" (token expired after 24h or already used)

**Validation:**
- Check database: `SELECT * FROM email_verifications WHERE user_id=1;`
- DAM event recorded: `SELECT * FROM dam_events WHERE action='email_verify';`

---

### Feature 2: 2FA (Two-Factor Authentication)

**Test Flow:**

1. **Request OTP code:**
   ```
   POST http://127.0.0.1:8000/mfa/request-otp
   Headers: Cookie: access_token=<your_token>
   Form: email=test@example.com
   ```
   
2. **Check logs for OTP code:**
   - Email printed to logs: "Your one-time code is: 123456"
   - OTP valid for 5 minutes
   
3. **Verify OTP:**
   ```
   POST http://127.0.0.1:8000/mfa/verify-otp
   Headers: Cookie: access_token=<your_token>
   Form: otp=123456
   ```
   - Success: "MFA verified"
   - Failure: "Invalid or expired OTP"

**Test Edge Cases:**
- Invalid OTP: `otp=000000` → "Invalid or expired OTP"
- Expired OTP: Wait 6+ minutes, try again → "Invalid or expired OTP"
- Correct OTP twice: Second attempt fails (token consumed)

**Validation:**
- Database: `SELECT * FROM mfa_tokens WHERE user_id=1;`
- DAM events: `SELECT * FROM dam_events WHERE action LIKE 'mfa_%';`

---

### Feature 3: Session Management

**Test Flow:**

1. **List active sessions:**
   ```
   GET http://127.0.0.1:8000/auth/sessions
   Headers: Cookie: access_token=<your_token>
   ```
   Returns: List of sessions with device_name, ip_address, created_at, last_activity_at

2. **Get session ID from response:**
   ```json
   {
     "sessions": [
       {
         "id": "1",
         "device_name": "Chrome on Windows",
         "ip_address": "127.0.0.1",
         "created_at": "2024-01-15T10:30:00",
         "last_activity_at": "2024-01-15T10:35:00"
       }
     ]
   }
   ```

3. **Logout specific session:**
   ```
   POST http://127.0.0.1:8000/auth/sessions/1/logout
   Headers: Cookie: access_token=<your_token>
   ```
   Returns: "Session logged out"

4. **Logout all sessions (except current):**
   ```
   POST http://127.0.0.1:8000/auth/logout-all?except_current=true
   Headers: Cookie: access_token=<your_token>
   ```
   Returns: "Logged out 2 sessions" (count may vary)

**Validation:**
- Database: `SELECT * FROM user_sessions WHERE user_id=1 AND is_active=1;`
- After logout: `SELECT * FROM user_sessions WHERE user_id=1 AND is_active=0;`

---

### Feature 4: Analytics Dashboard

**Test Flow:**

1. **View dashboard (admin only):**
   ```
   GET http://127.0.0.1:8000/analytics/dashboard
   Headers: Cookie: access_token=<admin_token>
   ```
   Returns:
   ```json
   {
     "total_users": 5,
     "total_files": 23,
     "total_events": 1240,
     "events_24h": 45,
     "new_users_24h": 2,
     "uploads_24h": 8,
     "downloads_24h": 15,
     "failed_logins_24h": 1,
     "high_severity_events_24h": 3,
     "critical_events_24h": 0,
     "top_files": [
       {"file_name": "report.pdf", "access_count": 12},
       {"file_name": "data.xlsx", "access_count": 8}
     ]
   }
   ```

2. **View user activity:**
   ```
   GET http://127.0.0.1:8000/analytics/me
   Headers: Cookie: access_token=<your_token>
   ```
   Returns:
   ```json
   {
     "uploads": 3,
     "downloads": 12,
     "shares": 2,
     "failed_logins": 0,
     "recent_ips": ["127.0.0.1"],
     "last_activity": "2024-01-15T10:35:00"
   }
   ```

**Validation:**
- Dashboard visible to: admin, auditor roles (403 for regular users)
- User activity endpoint: accessible to own user or admin/auditor

---

### Feature 5: Activity Reports

**Test Flow:**

1. **Generate CSV report:**
   ```
   POST http://127.0.0.1:8000/reports/activity/csv?start_date=2024-01-01&end_date=2024-01-15
   Headers: Cookie: access_token=<your_token>
   ```
   Returns:
   ```json
   {
     "report_id": "abc123",
     "file_path": "data/reports/abc123.csv",
     "format": "csv"
   }
   ```

2. **Generate JSON report (same parameters):**
   ```
   POST http://127.0.0.1:8000/reports/activity/json?start_date=2024-01-01&end_date=2024-01-15
   Headers: Cookie: access_token=<your_token>
   ```
   Returns:
   ```json
   {
     "report_id": "def456",
     "file_path": "data/reports/def456.json",
     "format": "json"
   }
   ```

3. **Check generated files:**
   ```bash
   ls -la data/reports/
   cat data/reports/abc123.csv
   ```

4. **Optional: Download report (endpoint needed):**
   ```
   GET http://127.0.0.1:8000/reports/abc123/download
   ```

**Report Content:**
CSV columns: event_id, created_at, actor_email, action, status, file_name, source_ip, severity

JSON structure:
```json
{
  "report_id": "abc123",
  "user_id": 1,
  "start_date": "2024-01-01",
  "end_date": "2024-01-15",
  "events": [
    {
      "event_id": "evt_123",
      "timestamp": "2024-01-15T10:30:00",
      "actor_email": "user@example.com",
      "action": "file_upload",
      "status": "success",
      "file_name": "document.pdf",
      "source_ip": "192.168.1.1",
      "severity": "low"
    }
  ]
}
```

**Validation:**
- Files created in `data/reports/` directory
- Report metadata in database: `SELECT * FROM activity_reports;`
- Reports expire after 7 days and are auto-deleted

---

### Feature 6: Data Retention

**Test Flow:**

1. **Check current log size:**
   ```bash
   sqlite3 data/app.db "SELECT COUNT(*) FROM dam_events;"
   ```

2. **Verify retention policy in config:**
   - `LOG_RETENTION_DAYS=90` (keep last 90 days of logs)
   - `SESSION_MAX_AGE_HOURS=24` (sessions expire after 24 hours)

3. **View cleanup audit trail:**
   ```bash
   sqlite3 data/app.db "SELECT * FROM log_cleanup_runs ORDER BY run_date DESC LIMIT 5;"
   ```

4. **Simulate old events (testing only):**
   ```bash
   sqlite3 data/app.db "
   INSERT INTO dam_events (event_type, severity, action, status, actor_user_id, created_at, event_hash, previous_event_hash, signature)
   VALUES ('test', 'low', 'test_old_event', 'success', 1, datetime('now', '-100 days'), 'hash1', '', 'sig1');
   "
   ```

5. **Run retention cleanup (manual trigger for testing):**
   ```python
   from app.database import get_db
   from app.services.retention import run_data_retention_cleanup
   
   with get_db() as conn:
       run_data_retention_cleanup(conn)
   ```

6. **Verify cleanup results:**
   ```bash
   sqlite3 data/app.db "SELECT * FROM log_cleanup_runs ORDER BY run_date DESC LIMIT 1;"
   ```

**Expected Behavior:**
- Events older than 90 days deleted
- Sessions without activity for 24+ hours marked inactive
- Cleanup operation logged to log_cleanup_runs table
- DAM event integrity verified (hash-chain preserved)

---

### Feature 7: Telegram Alerts (Optional)

**Setup (requires Telegram bot):**

1. Create bot via [@BotFather](https://t.me/BotFather)
2. Get bot token: `123456789:ABCdefGHIjklmNOpqrSTUvWXYZ-1234567890`
3. Get chat ID: Send message to bot, then:
   ```bash
   curl https://api.telegram.org/bot<TOKEN>/getUpdates
   ```
4. Update .env:
   ```
   TELEGRAM_ENABLED=true
   TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklmNOpqrSTUvWXYZ-1234567890
   TELEGRAM_CHAT_IDS=123456789,987654321
   ```

**Test Alert:**

Generate a critical DAM event (e.g., unauthorized file access):

```python
from app.database import get_db
from app.services.notifications import send_security_alert

send_security_alert(
    subject="[DAM] CRITICAL Unauthorized Access",
    body="User attempted to access restricted file from suspicious IP",
    recipients=["admin@example.com"],
    include_telegram=True
)
```

**Validation:**
- Alert received in Telegram app
- Check logs: "Sent telegram alert to chat_ids: [...]"

---

## Database Inspection

### Check all new tables:

```bash
sqlite3 data/app.db

# Email verifications
SELECT * FROM email_verifications;

# MFA tokens
SELECT * FROM mfa_tokens;

# User sessions
SELECT * FROM user_sessions;

# Activity reports
SELECT * FROM activity_reports;

# Cleanup audit trail
SELECT * FROM log_cleanup_runs;

# DAM events (check new features logged)
SELECT action, COUNT(*) FROM dam_events 
WHERE action IN ('email_verify', 'mfa_request', 'mfa_verify', 'report_generated', 'logout', 'logout_all')
GROUP BY action;
```

---

## Troubleshooting

### Issue: "Email verification token not sent"
- Check: `EMAIL_VERIFICATION_ENABLED=true` in .env
- Check: App logs for email content (printed to console in dev mode)
- Solution: Configure SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD for real emails

### Issue: "MFA OTP not working"
- Check: `MFA_ENABLED=true` in .env
- Check: `MFA_EXPIRY_MINUTES` - OTP expires quickly (default 5 min)
- Validate: OTP sent via configured SMTP or logged to console
- Solution: Ensure SMTP is configured or watch logs for OTP code

### Issue: "Sessions not persisting"
- Check: `SESSION_MAX_AGE_HOURS=24` in .env
- Verify: Session cookie being stored in browser
- Debug: `SELECT * FROM user_sessions WHERE user_id=1;` should show active sessions

### Issue: "Reports not generating"
- Check: `data/reports/` directory exists and is writable
- Verify: Date parameters format (ISO 8601: `2024-01-15`)
- Solution: Create directory: `mkdir -p data/reports`

### Issue: "Retention cleanup not running"
- Check: Lifespan task running (should see cleanup logs every hour)
- Verify: `LOG_RETENTION_DAYS` and `SESSION_MAX_AGE_HOURS` settings
- Manual trigger:
  ```python
  from app.database import get_db
  from app.services.retention import run_data_retention_cleanup
  with get_db() as conn:
      run_data_retention_cleanup(conn)
  ```

---

## Performance Notes

- **Email sending:** Non-blocking, logs failures but continues
- **Telegram alerts:** Async via httpx, timeout 5 seconds
- **Report generation:** Synchronous, may take seconds for large date ranges
- **Analytics queries:** Optimized with indexes on common filters
- **Retention cleanup:** Hourly, batch deletes to avoid locking

For production, consider:
- Move email/telegram to background job queue (Celery, RQ)
- Add pagination to report endpoints for large result sets
- Cache dashboard stats with 5-minute TTL
- Monitor cleanup job performance with large audit logs (1M+ events)

---

## Security Reminders

✅ **Always:**
- Use HTTPS in production (secure cookies require HTTPS)
- Store secrets in .env (never commit to git)
- Enable email verification for user registration
- Enable 2FA for sensitive operations
- Monitor DAM event logs regularly
- Keep retention policy aligned with compliance requirements

❌ **Never:**
- Disable hash-chain verification in production
- Store tokens plaintext (always hash before storing)
- Expose JWT secret or TELEGRAM_BOT_TOKEN
- Delete DAM audit logs before compliance period
- Allow unauthenticated access to analytics/reports endpoints

---

## Next Steps

1. ✅ Verify all features work with this guide
2. ✅ Update email templates for production formatting
3. ✅ Configure real SMTP and Telegram credentials
4. ✅ Run comprehensive test suite
5. ✅ Load test with realistic event volumes
6. ✅ Deploy to staging environment
7. ✅ Monitor and adjust retention policy
8. ✅ Move to production

---

**Last Updated:** 2024  
**Test Guide Version:** 1.0  
**Framework:** FastAPI + SQLite
