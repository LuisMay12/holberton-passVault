import base64, os
from datetime import datetime, timezone
from flask import request, jsonify, current_app, session
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import select
from extensions import db
from models import User, EmailVerificationToken
from crypto import hash_for_auth, verify_auth, derive_vault_key, new_email_token
from blueprints.auth import bp
from utils.jwt_config import create_access_token

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
        email_verified=True
    )
    db.session.add(user)
    db.session.flush()  # get user.id
    db.session.commit()
    
    return jsonify({"message": "signup ok"}), 201

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

    # if not user.email_verified:
    #     return jsonify({"error": "email not verified"}), 403

    vkey = derive_vault_key(master_password, user.kdf_salt)
    session["vault_key_b64"] = base64.b64encode(vkey).decode("ascii")

    # login_user(user, remember=False, duration=None)
    # session.permanent = True # this is in case we want to keep the session on by cookies, better not to do it in this case
    
    token = create_access_token(user.id)

    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "user": {"id": str(user.id), "email": user.email}
    })

# @bp.post("/logout")
# @login_required
# def logout():
#     """
#     Log out the current user and clear session data.

#     ---
#     **Endpoint:** POST /auth/logout  
#     **Description:**  
#     Logs out the current user and clears any stored encryption keys or session info.

#     **Headers:**
#     - Requires a valid Flask session cookie (used only for web session auth).

#     **Responses:**
#     - 200 OK  
#       ```json
#       {"message": "logged out"}
#       ```

#     **Notes:**
#     - This endpoint is only relevant when using session-based authentication.  
#       For JWT-based API clients, logging out simply means deleting the stored token client-side.
#     """
#     session.pop("vault_key_b64", None)
#     logout_user()
#     return jsonify({"message": "logged out"})
