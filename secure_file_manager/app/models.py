from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    role = db.Column(db.String(50), default='user')  # admin or user
    otp_secret = db.Column(db.String(32), nullable=True)
    email_verify_code = db.Column(db.String(12), nullable=True)
    email_verify_expires = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(128), nullable=True)
    oauth_provider = db.Column(db.String(30), nullable=True)
    oauth_id = db.Column(db.String(191), nullable=True)
    avatar_url = db.Column(db.String(500), nullable=True)
    public_key = db.Column(db.Text, nullable=True)  # PEM format
    encrypted_private_key = db.Column(db.Text, nullable=True)  # Encrypted with user password or something
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship('File', backref='owner', lazy=True)
    chat_messages = db.relationship('ChatMessage', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256
    is_public = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.Text, nullable=False)  # Encrypted AES key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    shares = db.relationship('Share', backref='file', lazy=True)

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    share_link = db.Column(db.String(500), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    expiry_date = db.Column(db.DateTime, nullable=True)
    max_downloads = db.Column(db.Integer, default=1)
    downloads_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # upload, download, share, etc.
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)