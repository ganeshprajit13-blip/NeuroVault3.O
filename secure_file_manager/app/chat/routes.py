import os
from flask import request, jsonify
from flask_login import login_required, current_user
from app import db, limiter
from app.chat import chat_bp
from app.models import ChatMessage
import requests


@chat_bp.route('/chat', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def chat():
    """Send a message to the chatbot."""
    data = request.get_json(silent=True)
    if not data or 'message' not in data:
        return jsonify({'error': 'Message is required'}), 400

    message = str(data['message']).strip()
    if not message or len(message) > 500:
        return jsonify({'error': 'Message must be 1-500 characters'}), 400

    try:
        response_text = get_chat_response(message)
        chat_msg = ChatMessage(
            user_id=current_user.id,
            message=message,
            response=response_text
        )
        db.session.add(chat_msg)
        db.session.commit()
        return jsonify({'response': response_text})
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Unable to process chat right now. Please try again.'}), 500


@chat_bp.route('/chat/history', methods=['GET'])
@login_required
def chat_history():
    """Retrieve chat history for the current user."""
    try:
        messages = (
            ChatMessage.query.filter_by(user_id=current_user.id)
            .order_by(ChatMessage.timestamp)
            .limit(50)
            .all()
        )
        return jsonify([
            {
                'id': msg.id,
                'message': msg.message,
                'response': msg.response,
                'timestamp': msg.timestamp.isoformat()
            }
            for msg in messages
        ])
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500


def get_chat_response(message):
    """Call configured chat provider and return assistant text."""
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
            return "No API key configured. Set GROQ_API_KEY, OPENROUTER_API_KEY, or GROK_API_KEY."

    if provider == 'openrouter':
        api_key = openrouter_key
        if not api_key:
            return "OpenRouter API key is not configured. Set OPENROUTER_API_KEY and try again."
        model = _env_value('OPENROUTER_MODEL', 'openrouter/auto')
        endpoint = _env_value('OPENROUTER_API_BASE', 'https://openrouter.ai/api/v1').rstrip('/') + '/chat/completions'
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    elif provider == 'groq':
        api_key = groq_key
        if not api_key:
            return "Groq API key is not configured. Set GROQ_API_KEY and try again."
        model = _env_value('GROQ_MODEL', 'llama-3.1-8b-instant')
        endpoint = _env_value('GROQ_API_BASE', 'https://api.groq.com/openai/v1').rstrip('/') + '/chat/completions'
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    else:
        api_key = grok_key
        if not api_key:
            return "Grok API key is not configured. Set GROK_API_KEY and try again."
        model = _env_value('GROK_MODEL', 'grok-3-mini')
        endpoint = _env_value('GROK_API_BASE', 'https://api.x.ai/v1').rstrip('/') + '/chat/completions'
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    system_prompt = (
        "You are a concise assistant for a secure file manager app. "
        "Help with upload, download, sharing, and troubleshooting. "
        "Never ask users for passwords or secret keys."
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message}
        ],
        "temperature": 0.4,
        "max_tokens": 300
    }

    response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
    if response.status_code != 200:
        try:
            err = response.json()
            err_msg = err.get('error') or err.get('message') or str(err)
        except ValueError:
            err_msg = response.text[:300] or "Unknown API error"

        provider_name = "OpenRouter" if provider == "openrouter" else ("Groq" if provider == "groq" else "Grok")
        if response.status_code in (401, 403):
            return f"{provider_name} API access error ({response.status_code}): {err_msg}"
        return f"{provider_name} API request failed ({response.status_code}): {err_msg}"

    data = response.json()
    return (
        data.get('choices', [{}])[0]
        .get('message', {})
        .get('content', '')
        .strip()
    ) or "I could not generate a response. Please try rephrasing your question."


def _env_value(key, default=''):
    """Read from process environment, then fallback to .env file."""
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
