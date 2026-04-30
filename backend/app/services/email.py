"""
Email service with SendGrid HTTP API support (works on Render free tier).
Falls back to logging if SendGrid fails.
"""

import requests
from typing import Optional
from ..config import get_settings
from .audit import get_logger

logger = get_logger()


def send_email_via_sendgrid(
    to_email: str,
    subject: str,
    html_content: str,
    from_email: Optional[str] = None
) -> bool:
    """
    Send email using SendGrid API (HTTP-based, works on Render).
    
    Returns:
        True if email sent successfully, False otherwise
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
            "personalizations": [
                {
                    "to": [{"email": to_email}],
                    "subject": subject
                }
            ],
            "from": {"email": from_email},
            "content": [
                {
                    "type": "text/html",
                    "value": html_content
                }
            ]
        }
        
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        
        if response.status_code in (200, 201, 202):
            logger.info("Email sent successfully to %s via SendGrid", to_email)
            return True
        else:
            logger.error(
                "SendGrid API error: %s - %s",
                response.status_code,
                response.text
            )
            return False
            
    except requests.exceptions.Timeout:
        logger.error("SendGrid request timeout for %s", to_email)
        return False
    except requests.exceptions.ConnectionError as e:
        logger.error("SendGrid connection error: %s", e)
        return False
    except Exception as e:
        logger.error("Unexpected error sending email via SendGrid: %s", e)
        return False


def send_otp_email(email: str, otp: str) -> bool:
    """
    Send OTP verification email.
    
    Returns:
        True if sent successfully, False if failed (but registration still allowed)
    """
    settings = get_settings()
    
    # HTML email template
    html_content = f"""
    <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #0f172a; color: #e2e8f0; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background-color: #f5f5f5; }}
                .otp-box {{ background-color: #0f172a; color: #e2e8f0; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; margin: 20px 0; }}
                .footer {{ text-align: center; color: #666; font-size: 12px; padding: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>SecureVault Registration</h1>
                </div>
                <div class="content">
                    <p>Hi {email},</p>
                    <p>Your verification code for SecureVault registration is:</p>
                    <div class="otp-box">{otp}</div>
                    <p>This code will expire in <strong>5 minutes</strong>.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2026 SecureVault. All rights reserved.</p>
                </div>
            </div>
        </body>
    </html>
    """
    
    success = send_email_via_sendgrid(
        to_email=email,
        subject="SecureVault Registration Verification Code",
        html_content=html_content
    )
    
    if not success:
        # Fallback: log OTP for debugging (don't expose in production logs)
        logger.warning("Email delivery failed for %s. OTP logged for debugging.", email)
    
    return success


def test_email_connection() -> dict:
    """
    Test email configuration and connectivity.
    Returns status and diagnostic information.
    """
    settings = get_settings()
    
    result = {
        "email_provider": settings.email_provider,
        "smtp_enabled": settings.smtp_enabled,
        "sendgrid_configured": bool(settings.sendgrid_api_key),
        "status": "unknown"
    }
    
    if settings.email_provider == "sendgrid":
        if not settings.sendgrid_api_key:
            result["status"] = "error"
            result["error"] = "SendGrid API key not configured"
            return result
        
        try:
            # Test SendGrid API connectivity
            url = "https://api.sendgrid.com/v3/mail/send"
            headers = {
                "Authorization": f"Bearer {settings.sendgrid_api_key}",
                "Content-Type": "application/json"
            }
            
            # Send a minimal test request
            response = requests.get(
                "https://api.sendgrid.com/v3/api_keys",
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                result["status"] = "connected"
                result["message"] = "SendGrid API is accessible"
            elif response.status_code == 401:
                result["status"] = "error"
                result["error"] = "Invalid SendGrid API key"
            else:
                result["status"] = "error"
                result["error"] = f"SendGrid API returned status {response.status_code}"
                
        except requests.exceptions.Timeout:
            result["status"] = "error"
            result["error"] = "SendGrid API timeout"
        except requests.exceptions.ConnectionError:
            result["status"] = "error"
            result["error"] = "Cannot reach SendGrid API (network issue)"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
    
    else:
        result["status"] = "unsupported"
        result["error"] = f"Email provider '{settings.email_provider}' not supported"
    
    return result
