from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import inspect, text
from flask_dance.contrib.google import make_google_blueprint
from flask_dance.contrib.facebook import make_facebook_blueprint
import os

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
limiter = Limiter(key_func=get_remote_address)

def create_app():
    _load_env_file()
    app = Flask(__name__)
    app.config['SECRET_KEY'] = (os.environ.get('SECRET_KEY') or 'dev-secret-key').strip()
    
    # Database configuration - support both PostgreSQL (for Vercel) and SQLite (for local dev)
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # PostgreSQL for Vercel/production
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    else:
        # SQLite for local development
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_files.db'
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Use /tmp for Vercel serverless, otherwise use local uploads folder
    if os.environ.get('VERCEL'):
        app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
        os.makedirs('/tmp/uploads', exist_ok=True)
    else:
        app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 100 * 1024 * 1024))  # 100MB default
    # Use LAN URL (e.g. http://192.168.1.10:5000) so QR codes / share links work on phones, not 127.0.0.1
    app.config['PUBLIC_BASE_URL'] = (os.environ.get('PUBLIC_BASE_URL') or '').rstrip('/')
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    mail_username = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_USERNAME'] = mail_username
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = mail_username
    app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.environ.get('GOOGLE_OAUTH_CLIENT_ID', '')
    app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET', '')
    app.config['FACEBOOK_OAUTH_CLIENT_ID'] = os.environ.get('FACEBOOK_OAUTH_CLIENT_ID', '')
    app.config['FACEBOOK_OAUTH_CLIENT_SECRET'] = os.environ.get('FACEBOOK_OAUTH_CLIENT_SECRET', '')

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = 'auth.login'

    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from app.files import files as files_blueprint
    app.register_blueprint(files_blueprint, url_prefix='/files')

    from app.chat import chat_bp as chat_blueprint
    app.register_blueprint(chat_blueprint, url_prefix='/api')

    if app.config['GOOGLE_OAUTH_CLIENT_ID'] and app.config['GOOGLE_OAUTH_CLIENT_SECRET']:
        google_bp = make_google_blueprint(
            client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
            client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
            scope=['profile', 'email'],
            redirect_url='/auth/oauth/google/callback',
        )
        app.register_blueprint(google_bp, url_prefix='/login')

    if app.config['FACEBOOK_OAUTH_CLIENT_ID'] and app.config['FACEBOOK_OAUTH_CLIENT_SECRET']:
        facebook_bp = make_facebook_blueprint(
            client_id=app.config['FACEBOOK_OAUTH_CLIENT_ID'],
            client_secret=app.config['FACEBOOK_OAUTH_CLIENT_SECRET'],
            scope=['email'],
            redirect_url='/auth/oauth/facebook/callback',
        )
        app.register_blueprint(facebook_bp, url_prefix='/login')

    @app.route('/')
    def index():
        from flask_login import current_user
        if current_user.is_authenticated:
            return redirect(url_for('files.dashboard'))
        else:
            return redirect(url_for('auth.login'))

    with app.app_context():
        db.create_all()
        _ensure_user_email_verify_columns()

    return app


def _load_env_file():
    """Load key=value pairs from project .env into process environment."""
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, 'r', encoding='utf-8') as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        # App still works without .env; OS environment can be used instead.
        return


def _ensure_user_email_verify_columns():
    """Add auth-related columns to existing SQLite DBs (create_all does not alter tables)."""
    try:
        inspector = inspect(db.engine)
        if 'user' not in inspector.get_table_names():
            return
        cols = {c['name'] for c in inspector.get_columns('user')}
        if 'email_verify_code' not in cols:
            db.session.execute(text('ALTER TABLE user ADD COLUMN email_verify_code VARCHAR(12)'))
        if 'email_verify_expires' not in cols:
            db.session.execute(text('ALTER TABLE user ADD COLUMN email_verify_expires DATETIME'))
        if 'oauth_provider' not in cols:
            db.session.execute(text('ALTER TABLE user ADD COLUMN oauth_provider VARCHAR(30)'))
        if 'oauth_id' not in cols:
            db.session.execute(text('ALTER TABLE user ADD COLUMN oauth_id VARCHAR(191)'))
        if 'avatar_url' not in cols:
            db.session.execute(text('ALTER TABLE user ADD COLUMN avatar_url VARCHAR(500)'))
        db.session.commit()
    except Exception:
        db.session.rollback()