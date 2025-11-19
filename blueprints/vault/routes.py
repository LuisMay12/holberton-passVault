from flask import request, jsonify
from extensions import db
from models import VaultEntry
from crypto import encrypt_pwd, decrypt_pwd
from blueprints.vault import bp
from utils.jwt_config import jwt_required
from crypto import derive_vault_key
from blueprints.vault.schemes import RegisterCredentialBody, VaultListResponse, RegisterCredentialBody
# def _get_vault_key():
#     b64 = session.get("vault_key_b64")
#     if not b64:
#         abort(401, description="Not authenticated or session expired")
#     try:
#         return base64.b64decode(b64.encode("ascii"))
#     except Exception:
#         abort(401, description="Invalid session key")

def _aad(user_id, app_name):
    return f"{user_id}:{app_name}".encode("utf-8")


#@login_required # this is when using session auth
@bp.post("/register")
@jwt_required
def register_credential():
    user = request.user

    # Deserialize request body - only accept known fields
    data = request.get_json(force=True, silent=True) or {}
    body = RegisterCredentialBody(
        app_name=data.get("app_name", ""),
        password=data.get("password", ""),
        master_password=data.get("master_password", ""),
        app_login_url=data.get("app_login_url")
    )

    # Validate required fields
    if not body.app_name or not body.password:
        return jsonify({"error": "app_name and password required"}), 400
    if not body.master_password:
        return jsonify({"error": "master_password required"}), 400

    if VaultEntry.query.filter_by(user_id=user.id, app_name=body.app_name).first():
        return jsonify({"error": "app already exists"}), 409

    vkey = derive_vault_key(body.master_password, user.kdf_salt)
    nonce, blob = encrypt_pwd(vkey, body.password, _aad(user.id, body.app_name))

    entry = VaultEntry(
        user_id=user.id,
        app_name=body.app_name,
        app_login_url=body.app_login_url or None,
        nonce=nonce,
        enc_password=blob,
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({"id": str(entry.id), "app_name": entry.app_name}), 201


@bp.get("/list")
@jwt_required
def list_apps():
    user = request.user
    rows = (
        VaultEntry.query
        .with_entities(VaultEntry.app_name, VaultEntry.id)
        .filter_by(user_id=user.id)
        .order_by(VaultEntry.created_at.asc())
        .all()
    )
    response: VaultListResponse = {
        "apps": [
            {"name": r.app_name, "id": str(r.id)}
            for r in rows
        ]
    }
    return jsonify(response), 200


@bp.get("/detail/<uuid:register_id>")
@jwt_required
def detail(register_id):
    user = request.user

    entry = VaultEntry.query.filter_by(user_id=user.id, id=register_id).first()
    if not entry:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(force=True, silent=True) or {}
    
    # If master_password is provided, decrypt and return password
    if "master_password" in data and data["master_password"]:
        vkey = derive_vault_key(data["master_password"], user.kdf_salt)
        password = decrypt_pwd(vkey, entry.nonce, entry.enc_password, _aad(user.id, entry.app_name))
        return jsonify({
            "id": str(entry.id),
            "app_name": entry.app_name,
            "app_login_url": entry.app_login_url,
            "password": password,
            "created_at": entry.created_at.isoformat() if entry.created_at else None,
            "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
        }), 200
    
    # Otherwise, return basic info without password
    return jsonify({
        "id": str(entry.id),
        "app_name": entry.app_name,
        "app_login_url": entry.app_login_url,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
    }), 200


@bp.put("/update/<uuid:register_id>")
@jwt_required
def update_credential(register_id):
    user = request.user
    data = request.get_json(force=True, silent=True) or {}
    master_password = data.get("master_password")
    if not master_password:
        return jsonify({"error": "master_password required"}), 400

    # Fetch entry by ID, ensuring ownership
    entry = VaultEntry.query.filter_by(id=register_id, user_id=user.id).first()
    if not entry:
        return jsonify({"error": "entry not found"}), 404

    # Derive vault key to decrypt/re-encrypt
    try:
        vkey = derive_vault_key(master_password, user.kdf_salt)
    except Exception:
        return jsonify({"error": "invalid master_password"}), 401

    # Update allowed fields if provided
    updated = False

    new_app_name = (data.get("app_name") or "").strip()
    new_app_login_url = (data.get("app_login_url") or "").strip()
    new_password = data.get("password")

    # Validate unique app_name (if changed)
    if new_app_name and new_app_name != entry.app_name:
        exists = VaultEntry.query.filter_by(user_id=user.id, app_name=new_app_name).first()
        if exists:
            return jsonify({"error": "app_name already exists"}), 409
        entry.app_name = new_app_name
        updated = True

    if new_app_login_url:
        entry.app_login_url = new_app_login_url
        updated = True

    if new_password:
        nonce, blob = encrypt_pwd(vkey, new_password, f"{user.id}:{entry.app_name}".encode())
        entry.nonce = nonce
        entry.enc_password = blob
        updated = True

    if not updated:
        return jsonify({"message": "No fields updated"}), 200

    db.session.commit()
    return jsonify({"message": "Credential updated successfully"}), 200
