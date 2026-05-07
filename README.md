# 🛡️ SecureVault Pro

SecureVault Pro is an advanced security platform for file storage, auditing, and threat detection.

## 🚀 How to Run locally

### Quick Start (Windows)
1. Double-click **`run_backend.bat`** to start the FastAPI server.
2. Double-click **`run_frontend.bat`** to start the React/Vite development server.
3. Open `http://localhost:5173` in your browser.

### Manual Start
**Backend:**
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Frontend:**
```bash
cd frontend
npm run dev
```

## ✨ Key Features
- **Audit Logging**: Every request, response, and UI interaction is logged in the `dam_events` table.
- **Malware Scanning**: Integrated with VirusTotal for real-time file scanning.
- **Secure Sharing**: Password-protected and expiring download links with QR codes.
- **SMTP Alerts**: Real-time email notifications for security incidents.
- **RBAC**: Admin and User roles with different access levels.

## 🛠️ Tech Stack
- **Frontend**: React, Vite, Tailwind CSS
- **Backend**: FastAPI (Python), SQLite/PostgreSQL
- **Security**: JWT, Bcrypt, Audit Middleware

## 👥 Team Responsibilities
- **Backend & Infrastructure**: Implementation of Audit trails, Virus scanning, and Security middlewares.
- **Frontend Core**: Vault management and Secure sharing pages.
- **Frontend Admin**: Monitoring dashboard and System settings.
