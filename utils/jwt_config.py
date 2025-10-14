import jwt
from datetime import datetime, timedelta, timezone
from flask import current_app, request, jsonify
from functools import wraps
from models import User
from extensions import db

def create_access_token(user_id):
    """Create short-lived access token (Bearer JWT)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=current_app.config["JWT_EXP_MINUTES"]),
    }
    token = jwt.encode(
        payload,
        current_app.config["JWT_SECRET_KEY"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )
    return token

def decode_token(token):
    """Return payload if valid, raise jwt exceptions otherwise."""
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET_KEY"],
        algorithms=[current_app.config["JWT_ALGORITHM"]],
    )

def jwt_required(func):
    """Decorator to protect endpoints with Bearer token."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        user = db.session.get(User, payload["sub"])
        if not user:
            return jsonify({"error": "User not found"}), 401
        request.user = user
        return func(*args, **kwargs)
    return wrapper
