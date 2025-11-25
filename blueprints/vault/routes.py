from flask import request, jsonify
from extensions import db
from models import VaultEntry
from crypto import encrypt_pwd, decrypt_pwd
from blueprints.vault import bp
from utils.jwt_config import jwt_required
from crypto import derive_vault_key
from blueprints.vault.schemes import RegisterCredentialBody, VaultListResponse

def _aad(user_id, app_name):
    return f"{user_id}:{app_name}".encode("utf-8")


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
    """Get basic credential info without password"""
    user = request.user

    entry = VaultEntry.query.filter_by(user_id=user.id, id=register_id).first()
    if not entry:
        return jsonify({"error": "not found"}), 404

    # Return basic info without password (GET doesn't support body reliably)
    return jsonify({
        "id": str(entry.id),
        "app_name": entry.app_name,
        "app_login_url": entry.app_login_url,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
    }), 200


@bp.post("/detail/<uuid:register_id>/reveal")
@jwt_required
def reveal_password(register_id):
    """Reveal decrypted password using master password"""
    user = request.user

    entry = VaultEntry.query.filter_by(user_id=user.id, id=register_id).first()
    if not entry:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(force=True, silent=True) or {}
    master_password = data.get("master_password", "").strip()
    
    if not master_password:
        return jsonify({"error": "master_password required"}), 400

    try:
        vkey = derive_vault_key(master_password, user.kdf_salt)
        aad = _aad(user.id, entry.app_name)
        
        # Verify we have the required data
        if not entry.nonce or not entry.enc_password:
            return jsonify({"error": "encrypted data missing"}), 500
        
        password = decrypt_pwd(vkey, entry.nonce, entry.enc_password, aad)
        
        # Verify password was decrypted successfully
        if password is None:
            return jsonify({"error": "decryption failed - returned None"}), 500
        
        if password == "":
            return jsonify({"error": "decryption failed - empty result"}), 500
        
        return jsonify({
            "id": str(entry.id),
            "app_name": entry.app_name,
            "app_login_url": entry.app_login_url,
            "password": password,
            "created_at": entry.created_at.isoformat() if entry.created_at else None,
            "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
        }), 200
    except ValueError:
        # Decryption failed - wrong master password
        return jsonify({"error": "invalid master password"}), 401
    except Exception as e:
        # Other errors
        return jsonify({"error": f"decryption error: {str(e)}"}), 500


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
        nonce, blob = encrypt_pwd(vkey, new_password, _aad(user.id, entry.app_name))
        entry.nonce = nonce
        entry.enc_password = blob
        updated = True

    if not updated:
        return jsonify({"message": "No fields updated"}), 200

    db.session.commit()
    return jsonify({"message": "Credential updated successfully"}), 200
