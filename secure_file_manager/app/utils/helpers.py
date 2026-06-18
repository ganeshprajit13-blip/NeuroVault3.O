import pyotp
import qrcode
import io
from flask_mail import Message
from app import mail
import secrets
import string
from datetime import datetime, timedelta
from app import db
from app.models import Log
import hashlib
from flask import current_app

def generate_otp_secret():
    """Generate a secret for TOTP"""
    return pyotp.random_base32()

def generate_otp(secret):
    """Generate OTP from secret"""
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_otp(secret, otp):
    """Verify TOTP (allows one step before/after for clock skew)."""
    totp = pyotp.TOTP(secret)
    return totp.verify(otp, valid_window=1)


def generate_email_verification_code():
    """Six-digit code for email verification (not time-based; stays valid until expiry)."""
    return "".join(secrets.choice("0123456789") for _ in range(6))

def send_email(subject, recipients, body):
    """Send email using Flask-Mail. Returns True if sent, False if skipped or failed."""
    username = current_app.config.get('MAIL_USERNAME')
    if not username:
        current_app.logger.warning(
            "Email not sent (set MAIL_USERNAME and MAIL_PASSWORD): %s to %s",
            subject,
            recipients,
        )
        return False
    sender = current_app.config.get('MAIL_DEFAULT_SENDER') or username
    msg = Message(subject, recipients=recipients, body=body, sender=sender)
    try:
        mail.send(msg)
        return True
    except Exception:
        current_app.logger.exception("Failed to send email to %s", recipients)
        return False

def generate_secure_link():
    """Generate a secure random link"""
    return secrets.token_urlsafe(32)

def generate_qr_code(data, box_size=12, border=4):
    """Generate QR code PNG stream (larger boxes scan more reliably on phone cameras)."""
    qr = qrcode.QRCode(version=1, box_size=box_size, border=border)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf

def hash_password(password):
    """Hash password using SHA-256 (but actually use bcrypt in models)"""
    return hashlib.sha256(password.encode()).hexdigest()

def log_activity(user_id, action, file_id=None, ip_address=None, details=None):
    """Log user activity"""
    log = Log(
        user_id=user_id,
        action=action,
        file_id=file_id,
        ip_address=ip_address,
        details=details
    )
    db.session.add(log)
    db.session.commit()

def check_file_integrity(data, expected_hash):
    """Verify SHA-256 of data (e.g. decrypted plaintext) matches the stored hash."""
    actual_hash = hashlib.sha256(data).hexdigest()
    return actual_hash == expected_hash