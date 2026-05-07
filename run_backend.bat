@echo off
echo ==========================================
echo    STARTING SECUREVAULT BACKEND
echo ==========================================
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
