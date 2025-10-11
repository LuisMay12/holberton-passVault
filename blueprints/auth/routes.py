import base64, os
from datetime import datetime, timezone
from flask import request, jsonify, current_app, session
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import select
from extensions import db
from models import User, EmailVerificationToken
from crypto import hash_for_auth, verify_auth, derive_vault_key, new_email_token
from blueprints.auth import bp

def _normalize_email(e: str) -> str:
    return (e or "").strip().lower()

@bp.post("/signup")
def signup():
    data = request.get_json(force=True, silent=True) or {}
    email = _normalize_email(data.get("email"))
    master_password = data.get("master_password") or ""

    if not email or not master_password:
        return jsonify({"error": "email and master_password required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "email already registered"}), 409

    user = User(
        email=email,
        pw_hash_auth=hash_for_auth(master_password),
        kdf_salt=os.urandom(16),
        email_verified=False
    )
    db.session.add(user)
    db.session.flush()  # get user.id

    token_str, expires_at = new_email_token()
    token = EmailVerificationToken(user_id=user.id, token=token_str, expires_at=expires_at)
    db.session.add(token)
    db.session.commit()

    # DEV ONLY: return the verification link so you can test quickly.
    verify_url = f"/auth/verify?token={token_str}"
    return jsonify({"message": "signup ok, verify email", "verify_url_dev": verify_url}), 201

@bp.get("/verify")
def verify():
    token_str = request.args.get("token", "")
    tok = EmailVerificationToken.query.filter_by(token=token_str).first()
    if not tok:
        return jsonify({"error": "invalid token"}), 400
    if tok.expires_at < datetime.now(timezone.utc):
        return jsonify({"error": "token expired"}), 400

    user = tok.user
    user.email_verified = True
    db.session.delete(tok)
    db.session.commit()
    return jsonify({"message": "email verified"})

@bp.post("/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    email = _normalize_email(data.get("email"))
    master_password = data.get("master_password") or ""

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "invalid credentials"}), 401

    try:
        verify_auth(user.pw_hash_auth, master_password)
    except Exception:
        return jsonify({"error": "invalid credentials"}), 401

    if not user.email_verified:
        return jsonify({"error": "email not verified"}), 403

    vkey = derive_vault_key(master_password, user.kdf_salt)
    session["vault_key_b64"] = base64.b64encode(vkey).decode("ascii")

    login_user(user, remember=False, duration=None)
    session.permanent = True
    return jsonify({"message": "login ok"})

@bp.post("/logout")
@login_required
def logout():
    session.pop("vault_key_b64", None)
    logout_user()
    return jsonify({"message": "logged out"})
