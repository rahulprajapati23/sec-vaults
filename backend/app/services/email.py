import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from typing import Optional
from ..config import get_settings
from .audit import get_logger

logger = get_logger()


def send_email_via_smtp(
    to_email: str,
    subject: str,
    html_content: str,
) -> bool:
    """Send email using standard SMTP (e.g. Gmail)."""
    settings = get_settings()
    if not settings.smtp_enabled:
        logger.error("SMTP is disabled in settings")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = settings.smtp_sender
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_content, 'html'))

        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)
        if settings.smtp_starttls:
            server.starttls()
        
        server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(msg)
        server.quit()
        
        logger.info("Email sent successfully to %s via SMTP", to_email)
        return True
    except Exception as e:
        logger.error("SMTP error: %s", e)
        return False


def send_email_via_sendgrid(
    to_email: str,
    subject: str,
    html_content: str,
    from_email: Optional[str] = None
) -> bool:
    """
    Send email using SendGrid API (HTTP-based, works on Render).
    """
    settings = get_settings()
    
    if not settings.sendgrid_api_key:
        logger.error("SendGrid API key not configured")
        return False
    
    from_email = from_email or settings.smtp_sender or "noreply@securevault.app"
    
    try:
        url = "https://api.sendgrid.com/v3/mail/send"
        headers = {
            "Authorization": f"Bearer {settings.sendgrid_api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "personalizations": [{"to": [{"email": to_email}], "subject": subject}],
            "from": {"email": from_email},
            "content": [{"type": "text/html", "value": html_content}]
        }
        
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        return response.status_code in (200, 201, 202)
            
    except Exception as e:
        logger.error("Unexpected error sending email via SendGrid: %s", e)
        return False


def send_otp_email(email: str, otp: str) -> bool:
    """Send OTP verification email."""
    settings = get_settings()
    
    html_content = f"""
    <html>
        <body style="font-family: sans-serif; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;">
                <div style="background: #0f172a; color: white; padding: 20px; text-align: center;">
                    <h2>SecureVault Verification</h2>
                </div>
                <div style="padding: 20px; text-align: center;">
                    <p>Your verification code is:</p>
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 4px; margin: 20px 0; color: #3b82f6;">{otp}</div>
                    <p style="color: #64748b; font-size: 14px;">This code will expire in 5 minutes.</p>
                </div>
            </div>
        </body>
    </html>
    """
    
    if settings.email_provider == "smtp":
        return send_email_via_smtp(email, "SecureVault Verification Code", html_content)
    return send_email_via_sendgrid(email, "SecureVault Verification Code", html_content)


def test_email_connection() -> dict:
    """Test email configuration."""
    settings = get_settings()
    
    result = {
        "email_provider": settings.email_provider,
        "status": "unknown"
    }
    
    if settings.email_provider == "smtp":
        try:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=5)
            if settings.smtp_starttls:
                server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
            server.quit()
            result["status"] = "connected"
            result["message"] = f"Successfully connected to {settings.smtp_host}"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
    elif settings.email_provider == "sendgrid":
        if not settings.sendgrid_api_key:
            result["status"] = "error"
            result["error"] = "SendGrid API key not configured"
        else:
            try:
                response = requests.get(
                    "https://api.sendgrid.com/v3/api_keys",
                    headers={"Authorization": f"Bearer {settings.sendgrid_api_key}"},
                    timeout=5
                )
                if response.status_code == 200:
                    result["status"] = "connected"
                else:
                    result["status"] = "error"
                    result["error"] = f"SendGrid error: {response.status_code}"
            except Exception as e:
                result["status"] = "error"
                result["error"] = str(e)
    
    return result

