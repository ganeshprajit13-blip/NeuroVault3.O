from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
from app.utils.helpers import generate_email_verification_code, send_email, log_activity
from flask_dance.contrib.google import google
from flask_dance.contrib.facebook import facebook
import secrets
from datetime import datetime, timedelta

auth = Blueprint('auth', __name__)


def _google_oauth_configured():
    return bool(current_app.config.get('GOOGLE_OAUTH_CLIENT_ID') and current_app.config.get('GOOGLE_OAUTH_CLIENT_SECRET'))


def _facebook_oauth_configured():
    return bool(current_app.config.get('FACEBOOK_OAUTH_CLIENT_ID') and current_app.config.get('FACEBOOK_OAUTH_CLIENT_SECRET'))


def _safe_username(base_name):
    candidate = (base_name or 'user').strip().lower().replace(' ', '_')
    candidate = ''.join(ch for ch in candidate if ch.isalnum() or ch == '_')[:24] or 'user'
    username = candidate
    suffix = 1
    while User.query.filter_by(username=username).first():
        suffix += 1
        username = f'{candidate[:20]}_{suffix}'
    return username


def _oauth_login_or_create(provider, provider_user_id, email, display_name, avatar_url=None):
    user = User.query.filter_by(oauth_provider=provider, oauth_id=str(provider_user_id)).first()
    if user:
        return user

    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            user.oauth_provider = provider
            user.oauth_id = str(provider_user_id)
            user.avatar_url = avatar_url
            if not user.is_verified:
                user.is_verified = True
            db.session.commit()
            return user

    username = _safe_username(display_name or (email.split('@')[0] if email else provider))
    user = User(
        username=username,
        email=email or f'{provider}_{provider_user_id}@local.oauth',
        oauth_provider=provider,
        oauth_id=str(provider_user_id),
        avatar_url=avatar_url,
        is_verified=True,
    )
    user.set_password(secrets.token_urlsafe(24))
    db.session.add(user)
    db.session.commit()
    return user

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        by_email = User.query.filter_by(email=email).first()
        by_username = User.query.filter_by(username=username).first()

        if by_email and by_email.is_verified:
            flash('This email is already registered. Log in or use Forgot password.')
            return redirect(url_for('auth.register'))

        if by_email and not by_email.is_verified:
            if by_username and by_username.id != by_email.id:
                flash('Username already exists')
                return redirect(url_for('auth.register'))
            user = by_email
            user.username = username
            user.set_password(password)
            msg_prefix = 'Account not verified yet. A new verification code has been sent.'
        else:
            if by_username:
                flash('Username already exists')
                return redirect(url_for('auth.register'))
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            msg_prefix = 'Registration successful. Check your email for the verification code.'

        otp = generate_email_verification_code()
        user.email_verify_code = otp
        user.email_verify_expires = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()

        sent = send_email(
            'Your verification code',
            [email],
            f'Your verification code is: {otp}\n\nIt expires in 15 minutes.',
        )

        if sent:
            flash(msg_prefix)
        elif not current_app.config.get('MAIL_USERNAME'):
            flash(
                f'{msg_prefix} Email is not configured (set MAIL_USERNAME and MAIL_PASSWORD). '
                f'Your verification code is: {otp}'
            )
        else:
            flash(
                f'{msg_prefix} The email could not be sent. Your verification code is: {otp}'
            )

        return redirect(url_for('auth.verify_otp_route', user_id=user.id))

    return render_template('register.html')

@auth.route('/verify_otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp_route(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        otp = (request.form.get('otp') or '').strip()
        if not user.email_verify_code or not user.email_verify_expires:
            flash('No verification pending for this account. Try registering again or log in.')
        elif datetime.utcnow() > user.email_verify_expires:
            flash('This code has expired. Register again to receive a new code.')
        elif (
            otp
            and user.email_verify_code
            and len(otp) == len(user.email_verify_code)
            and secrets.compare_digest(user.email_verify_code, otp)
        ):
            user.is_verified = True
            user.email_verify_code = None
            user.email_verify_expires = None
            db.session.commit()
            flash('Account verified successfully')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid code. Check the number and try again.')

    return render_template('verify_otp.html', user_id=user_id)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_verified:
            login_user(user)
            log_activity(user.id, 'login', ip_address=request.remote_addr)
            return redirect(url_for('files.dashboard'))
        else:
            flash('Invalid credentials or account not verified')

    oauth_google_enabled = _google_oauth_configured()
    oauth_facebook_enabled = _facebook_oauth_configured()
    return render_template(
        'login.html',
        oauth_google_enabled=oauth_google_enabled,
        oauth_facebook_enabled=oauth_facebook_enabled,
    )


@auth.route('/oauth/google')
def oauth_google():
    if not _google_oauth_configured():
        flash('Google login is not configured yet. Add GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in .env')
        return redirect(url_for('auth.login'))
    return redirect(url_for('google.login'))


@auth.route('/oauth/google/callback')
def oauth_google_callback():
    if not _google_oauth_configured():
        flash('Google login is not configured yet. Add GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in .env')
        return redirect(url_for('auth.login'))

    try:
        is_authorized = google.authorized
    except AttributeError:
        flash('Google OAuth is not available right now. Please try again after server restart.')
        return redirect(url_for('auth.login'))

    if not is_authorized:
        flash('Google authorization failed. Please try again.')
        return redirect(url_for('auth.login'))

    profile_resp = google.get('/oauth2/v2/userinfo')
    if not profile_resp.ok:
        flash('Could not fetch your Google profile. Please try again.')
        return redirect(url_for('auth.login'))

    profile = profile_resp.json()
    provider_user_id = profile.get('id')
    email = profile.get('email')
    display_name = profile.get('name') or (email.split('@')[0] if email else 'google_user')
    avatar_url = profile.get('picture')

    if not provider_user_id:
        flash('Google login failed due to missing user details.')
        return redirect(url_for('auth.login'))

    user = _oauth_login_or_create('google', provider_user_id, email, display_name, avatar_url)
    login_user(user)
    log_activity(user.id, 'oauth_google_login', ip_address=request.remote_addr)
    flash('Logged in with Google successfully.')
    return redirect(url_for('files.dashboard'))


@auth.route('/oauth/facebook')
def oauth_facebook():
    if not _facebook_oauth_configured():
        flash('Facebook login is not configured yet. Add FACEBOOK_OAUTH_CLIENT_ID and FACEBOOK_OAUTH_CLIENT_SECRET in .env')
        return redirect(url_for('auth.login'))
    return redirect(url_for('facebook.login'))


@auth.route('/oauth/facebook/callback')
def oauth_facebook_callback():
    if not _facebook_oauth_configured():
        flash('Facebook login is not configured yet. Add FACEBOOK_OAUTH_CLIENT_ID and FACEBOOK_OAUTH_CLIENT_SECRET in .env')
        return redirect(url_for('auth.login'))

    try:
        is_authorized = facebook.authorized
    except AttributeError:
        flash('Facebook OAuth is not available right now. Please try again after server restart.')
        return redirect(url_for('auth.login'))

    if not is_authorized:
        flash('Facebook authorization failed. Please try again.')
        return redirect(url_for('auth.login'))

    profile_resp = facebook.get('/me?fields=id,name,email,picture.type(large)')
    if not profile_resp.ok:
        flash('Could not fetch your Facebook profile. Please try again.')
        return redirect(url_for('auth.login'))

    profile = profile_resp.json()
    provider_user_id = profile.get('id')
    email = profile.get('email')
    display_name = profile.get('name') or (email.split('@')[0] if email else 'facebook_user')
    picture = (profile.get('picture') or {}).get('data') or {}
    avatar_url = picture.get('url')

    if not provider_user_id:
        flash('Facebook login failed due to missing user details.')
        return redirect(url_for('auth.login'))

    user = _oauth_login_or_create('facebook', provider_user_id, email, display_name, avatar_url)
    login_user(user)
    log_activity(user.id, 'oauth_facebook_login', ip_address=request.remote_addr)
    flash('Logged in with Facebook successfully.')
    return redirect(url_for('files.dashboard'))


@auth.route('/oauth/apple')
def oauth_apple():
    flash('Apple login will be available soon.')
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout', ip_address=request.remote_addr)
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate reset token (simplified)
            reset_token = secrets.token_urlsafe(32)
            user.reset_token = reset_token  # Assuming we add this field
            db.session.commit()
            reset_url = url_for('auth.reset_password', token=reset_token, _external=True)
            sent = send_email('Password Reset', [email], f'Reset link: {reset_url}')
            if sent:
                flash('Password reset email sent.')
            elif not current_app.config.get('MAIL_USERNAME'):
                flash(f'Email is not configured. Use this link to reset your password: {reset_url}')
            else:
                flash(f'Email could not be sent. Use this link to reset your password: {reset_url}')
        else:
            flash('Email not found')

    return render_template('forgot_password.html')

@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash('Invalid token')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        password = request.form.get('password')
        user.set_password(password)
        user.reset_token = None
        db.session.commit()
        flash('Password reset successfully')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html')