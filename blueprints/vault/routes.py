import base64
from flask import request, jsonify, abort, session
from flask_login import login_required, current_user
from extensions import db
from models import VaultEntry
from crypto import encrypt_pwd, decrypt_pwd
from blueprints.vault import bp

def _get_vault_key():
    b64 = session.get("vault_key_b64")
    if not b64:
        abort(401, description="Not authenticated or session expired")
    try:
        return base64.b64decode(b64.encode("ascii"))
    except Exception:
        abort(401, description="Invalid session key")

def _aad(user_id, app_name):
    return f"{user_id}:{app_name}".encode("utf-8")

@bp.post("/register")
@login_required
def register_credential():
    data = request.get_json(force=True, silent=True) or {}
    app_name = (data.get("app_name") or "").strip()
    app_login_url = (data.get("app_login_url") or "").strip()
    password = data.get("password") or ""

    if not app_name or not password:
        return jsonify({"error": "app_name and password required"}), 400

    if VaultEntry.query.filter_by(user_id=current_user.id, app_name=app_name).first():
        return jsonify({"error": "app already exists"}), 409

    vkey = _get_vault_key()
    nonce, blob = encrypt_pwd(vkey, password, _aad(current_user.id, app_name))

    entry = VaultEntry(
        user_id=current_user.id,
        app_name=app_name,
        app_login_url=app_login_url or None,
        nonce=nonce,
        enc_password=blob,
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({"id": str(entry.id), "app_name": entry.app_name}), 201

@bp.get("/list")
@login_required
def list_apps():
    rows = (VaultEntry.query
            .with_entities(VaultEntry.app_name)
            .filter_by(user_id=current_user.id)
            .order_by(VaultEntry.app_name.asc())
            .all())
    return jsonify({"apps": [r.app_name for r in rows]})

@bp.get("/detail")
@login_required
def detail():
    app_name = (request.args.get("app") or "").strip()
    if not app_name:
        return jsonify({"error": "app query param required"}), 400

    entry = VaultEntry.query.filter_by(user_id=current_user.id, app_name=app_name).first()
    if not entry:
        return jsonify({"error": "not found"}), 404

    vkey = _get_vault_key()
    password = decrypt_pwd(vkey, entry.nonce, entry.enc_password, _aad(current_user.id, app_name))

    return jsonify({
        "app_name": entry.app_name,
        "app_login_url": entry.app_login_url,
        "password": password
    })
