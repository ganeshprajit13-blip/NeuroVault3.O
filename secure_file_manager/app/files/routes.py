from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, abort, current_app, jsonify
from flask_login import login_required, current_user
from app import db
from app.models import File, Share, Log
from app.encryption.encryption import EncryptionManager
from app.utils.helpers import log_activity, check_file_integrity, generate_secure_link, generate_qr_code
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
import os
import io
import requests
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from cryptography.fernet import InvalidToken

files_bp = Blueprint('files', __name__)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'doc', 'docx', 'txt', 'mp3', 'mp4'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _resolved_storage_path(stored_path):
    """Absolute path in DB, or legacy path relative to project root (parent of app package)."""
    if os.path.isabs(stored_path):
        return stored_path
    project_root = os.path.dirname(current_app.root_path)
    return os.path.normpath(os.path.join(project_root, stored_path))


def _share_download_absolute_url(share_link):
    """URL encoded in QR codes — must be reachable from phones (not localhost unless testing on same device)."""
    path = url_for('files.shared_download', share_link=share_link)
    base = (current_app.config.get('PUBLIC_BASE_URL') or '').rstrip('/')
    if base:
        return base + path
    return url_for('files.shared_download', share_link=share_link, _external=True)


def _qr_routes_for_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    share = Share.query.filter_by(file_id=file_id).order_by(Share.id.desc()).first()
    if not share:
        return None, None, None
    return file, share, _share_download_absolute_url(share.share_link)


@files_bp.route('/dashboard')
@login_required
def dashboard():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    share_urls = {}
    for f in user_files:
        sh = Share.query.filter_by(file_id=f.id).order_by(Share.id.desc()).first()
        if sh:
            share_urls[f.id] = _share_download_absolute_url(sh.share_link)
    needs_lan_url = any(
        '127.0.0.1' in u or 'localhost' in u.lower()
        for u in share_urls.values()
    )
    return render_template(
        'dashboard.html',
        files=user_files,
        share_urls=share_urls,
        needs_lan_url=needs_lan_url,
    )


@files_bp.route('/recommendations', methods=['GET'])
@login_required
def recommendations():
    """Return AI recommendations for current user's file security workflow."""
    user_files = File.query.filter_by(user_id=current_user.id).all()
    recs = _generate_ai_recommendations(user_files)
    return jsonify({'recommendations': recs})

@files_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash(
                'File type not allowed. Use: '
                + ', '.join(sorted(ALLOWED_EXTENSIONS))
            )
            return redirect(request.url)

        filename = secure_filename(file.filename)
        if not filename:
            flash('Invalid file name. Use letters, numbers, and a normal file extension.')
            return redirect(request.url)

        file_data = file.read()

        enc_manager = EncryptionManager()
        aes_key = enc_manager.generate_aes_key()
        encrypted_data = enc_manager.encrypt_file(file_data, aes_key)

        encrypted_aes_key = enc_manager.seal_aes_key_for_storage(
            aes_key,
            current_app.config['SECRET_KEY'],
        )

        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, f"{current_user.id}_{filename}.enc")
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        file_hash = enc_manager.hash_file(file_data)

        new_file = File(
            filename=filename,
            original_filename=filename,
            file_path=file_path,
            file_size=len(file_data),
            file_hash=file_hash,
            encryption_key=encrypted_aes_key,
            user_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()

        log_activity(current_user.id, 'upload', file_id=new_file.id, ip_address=request.remote_addr)
        flash('File uploaded and encrypted successfully')
        return redirect(url_for('files.dashboard'))

    return render_template('upload.html', allowed_ext=sorted(ALLOWED_EXTENSIONS))

@files_bp.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id and not file.is_public:
        abort(403)

    enc_manager = EncryptionManager()
    try:
        aes_key = enc_manager.unwrap_stored_aes_key(
            file.encryption_key,
            current_app.config['SECRET_KEY'],
        )
    except InvalidToken:
        flash(
            'This file was encrypted with an older version of the app. '
            'Remove it from the list and upload it again.'
        )
        return redirect(url_for('files.dashboard'))
    storage_path = _resolved_storage_path(file.file_path)
    try:
        with open(storage_path, 'rb') as f:
            encrypted_data = f.read()
    except OSError:
        flash('Encrypted file is missing on the server. Upload the file again.')
        return redirect(url_for('files.dashboard'))
    try:
        decrypted_data = enc_manager.decrypt_file(encrypted_data, aes_key)
    except (ValueError, IndexError, TypeError):
        flash('Could not decrypt this file. Delete it and upload again.')
        return redirect(url_for('files.dashboard'))

    if not check_file_integrity(decrypted_data, file.file_hash):
        flash('File integrity compromised')
        return redirect(url_for('files.dashboard'))

    log_activity(current_user.id, 'download', file_id=file.id, ip_address=request.remote_addr)

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file.original_filename
    )

@files_bp.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)

    if request.method == 'POST':
        password = request.form.get('password')
        expiry_hours = int(request.form.get('expiry_hours', 24))
        max_downloads = int(request.form.get('max_downloads', 1))

        share_link = generate_secure_link()
        expiry_date = datetime.utcnow() + timedelta(hours=expiry_hours)

        share = Share(
            file_id=file_id,
            share_link=share_link,
            password_hash=generate_password_hash(password) if password else None,
            expiry_date=expiry_date,
            max_downloads=max_downloads
        )
        db.session.add(share)
        db.session.commit()

        log_activity(current_user.id, 'share', file_id=file.id, ip_address=request.remote_addr)
        flash('Share link created. Copy the link below — it works on your phone when using your Wi‑Fi URL.')
        return redirect(url_for('files.share', file_id=file_id))

    existing = Share.query.filter_by(file_id=file_id).order_by(Share.id.desc()).first()
    existing_share_url = (
        _share_download_absolute_url(existing.share_link) if existing else None
    )
    local_unusable = bool(
        existing_share_url
        and ('127.0.0.1' in existing_share_url or 'localhost' in existing_share_url.lower())
    )
    return render_template(
        'share.html',
        file=file,
        existing_share_url=existing_share_url,
        local_unusable=local_unusable,
    )

@files_bp.route('/shared/<share_link>', methods=['GET', 'POST'])
def shared_download(share_link):
    share = Share.query.filter_by(share_link=share_link).first_or_404()
    if share.expiry_date and datetime.utcnow() > share.expiry_date:
        abort(410)  # Gone
    if share.downloads_count >= share.max_downloads:
        abort(410)

    if share.password_hash:
        if request.method == 'POST':
            password = request.form.get('password')
            if not check_password_hash(share.password_hash, password):
                flash('Invalid password')
                return render_template('shared_download.html', share=share, requires_password=True)
        else:
            return render_template('shared_download.html', share=share, requires_password=True)

    file = share.file
    if file is None:
        return render_template('shared_unavailable.html', reason='missing'), 200

    enc_manager = EncryptionManager()
    try:
        aes_key = enc_manager.unwrap_stored_aes_key(
            file.encryption_key,
            current_app.config['SECRET_KEY'],
        )
    except InvalidToken:
        return render_template('shared_unavailable.html', reason='old_format'), 200

    storage_path = _resolved_storage_path(file.file_path)
    try:
        with open(storage_path, 'rb') as f:
            encrypted_data = f.read()
    except OSError:
        return render_template('shared_unavailable.html', reason='missing'), 200

    try:
        decrypted_data = enc_manager.decrypt_file(encrypted_data, aes_key)
    except (ValueError, IndexError, TypeError) as exc:
        current_app.logger.warning('shared_download decrypt failed: %s', exc)
        return render_template('shared_unavailable.html', reason='decrypt'), 200

    if not check_file_integrity(decrypted_data, file.file_hash):
        return render_template('shared_unavailable.html', reason='integrity'), 200

    share.downloads_count += 1
    db.session.commit()

    log_activity(None, 'shared_download', file_id=file.id, ip_address=request.remote_addr)

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file.original_filename
    )

@files_bp.route('/qr/<int:file_id>')
@login_required
def generate_qr(file_id):
    file, share, share_url = _qr_routes_for_file(file_id)
    if not share:
        flash('Create a share link first (Share), then open QR Code.')
        return redirect(url_for('files.dashboard'))
    local_unusable = '127.0.0.1' in share_url or 'localhost' in share_url.lower()
    return render_template(
        'qr_show.html',
        file=file,
        share_url=share_url,
        local_unusable=local_unusable,
    )


@files_bp.route('/qr/<int:file_id>/image.png')
@login_required
def qr_image(file_id):
    file, share, share_url = _qr_routes_for_file(file_id)
    if not share:
        abort(404)
    qr_buf = generate_qr_code(share_url)
    return send_file(qr_buf, mimetype='image/png', max_age=0)

@files_bp.route('/delete/<int:file_id>', methods=['POST', 'GET'])
@login_required
def delete(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    
    # Delete the encrypted file from storage
    storage_path = _resolved_storage_path(file.file_path)
    try:
        if os.path.exists(storage_path):
            os.remove(storage_path)
    except OSError as e:
        current_app.logger.error(f'Failed to delete file: {e}')
    
    # Delete associated shares
    Share.query.filter_by(file_id=file_id).delete()
    
    # Delete the file record from database
    db.session.delete(file)
    db.session.commit()
    
    log_activity(current_user.id, 'delete', file_id=file_id, ip_address=request.remote_addr)
    flash('File deleted successfully')
    return redirect(url_for('files.dashboard'))


def _generate_ai_recommendations(user_files):
    """Generate concise recommendations; fallback to deterministic tips if API fails."""
    if not user_files:
        return [
            "Upload your first file to enable personalized recommendations.",
            "Use share links with passwords for sensitive files.",
            "Set short expiry and low max downloads for safer sharing.",
        ]

    file_summaries = []
    for f in user_files[:20]:
        share_count = Share.query.filter_by(file_id=f.id).count()
        file_summaries.append(
            f"{f.original_filename} ({max(1, round(f.file_size / 1024))} KB, shares={share_count})"
        )

    prompt = (
        "Given this secure file manager usage, suggest 3 short actionable recommendations "
        "to improve privacy, sharing hygiene, and organization.\n"
        "Files:\n- " + "\n- ".join(file_summaries)
    )

    ai_text = _request_chat_completion(prompt)
    if not ai_text:
        return [
            "Protect sensitive shares with a password and short expiry time.",
            "Delete stale files and expired shares to reduce exposure.",
            "Use clear file names and folder grouping to improve retrieval speed.",
        ]

    rec_lines = [line.strip("- ").strip() for line in ai_text.splitlines() if line.strip()]
    cleaned = [line for line in rec_lines if len(line) > 8][:3]
    if len(cleaned) < 3:
        cleaned = [
            "Protect sensitive shares with password + expiry.",
            "Review old shared links weekly and remove unused ones.",
            "Organize uploads with clear names and file categories.",
        ]
    return cleaned


def _request_chat_completion(user_prompt):
    provider = (_env_value('CHAT_PROVIDER') or '').strip().lower()
    openrouter_key = (_env_value('OPENROUTER_API_KEY') or '').strip()
    grok_key = (_env_value('GROK_API_KEY') or '').strip()
    groq_key = (_env_value('GROQ_API_KEY') or '').strip()

    if not provider:
        if openrouter_key:
            provider = 'openrouter'
        elif groq_key:
            provider = 'groq'
        elif grok_key:
            provider = 'grok'
        else:
            return ''

    if provider == 'openrouter':
        if not openrouter_key:
            return ''
        model = _env_value('OPENROUTER_MODEL', 'openrouter/auto')
        endpoint = _env_value('OPENROUTER_API_BASE', 'https://openrouter.ai/api/v1').rstrip('/') + '/chat/completions'
        headers = {
            "Authorization": f"Bearer {openrouter_key}",
            "Content-Type": "application/json"
        }
    elif provider == 'groq':
        if not groq_key:
            return ''
        model = _env_value('GROQ_MODEL', 'llama-3.1-8b-instant')
        endpoint = _env_value('GROQ_API_BASE', 'https://api.groq.com/openai/v1').rstrip('/') + '/chat/completions'
        headers = {
            "Authorization": f"Bearer {groq_key}",
            "Content-Type": "application/json"
        }
    else:
        if not grok_key:
            return ''
        model = _env_value('GROK_MODEL', 'grok-3-mini')
        endpoint = _env_value('GROK_API_BASE', 'https://api.x.ai/v1').rstrip('/') + '/chat/completions'
        headers = {
            "Authorization": f"Bearer {grok_key}",
            "Content-Type": "application/json"
        }

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a concise security assistant for a secure file sharing app."
            },
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.4,
        "max_tokens": 180
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=20)
        if response.status_code != 200:
            return ''
        data = response.json()
        return (
            data.get('choices', [{}])[0]
            .get('message', {})
            .get('content', '')
            .strip()
        )
    except Exception:
        return ''


def _env_value(key, default=''):
    val = os.environ.get(key)
    if val is not None and str(val).strip() != '':
        return str(val).strip()

    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '.env'))
    if not os.path.exists(env_path):
        return default

    try:
        with open(env_path, 'r', encoding='utf-8') as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                if k.strip() == key:
                    return v.strip().strip('"').strip("'")
    except OSError:
        return default

    return default