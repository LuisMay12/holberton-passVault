import os, base64, secrets
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1) Authentication hash (verify at login)
# tune memory/time per your server; these are decent dev defaults
AUTH_PH = PasswordHasher(time_cost=3, memory_cost=102400, parallelism=8, hash_len=32)

def hash_for_auth(master_password: str) -> str:
    return AUTH_PH.hash(master_password)

def verify_auth(hash_str: str, candidate: str) -> bool:
    return AUTH_PH.verify(hash_str, candidate)

# 2) Derive per-user vault key via Argon2id KDF
def derive_vault_key(master_password: str, kdf_salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=kdf_salt,
        time_cost=4, memory_cost=262_144, parallelism=4,
        hash_len=32, type=Type.ID
    )

# 3) AES-GCM encrypt/decrypt
def encrypt_pwd(vault_key: bytes, plaintext_pwd: str, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(vault_key)
    ct = aesgcm.encrypt(nonce, plaintext_pwd.encode("utf-8"), aad)
    return nonce, ct

def decrypt_pwd(vault_key: bytes, nonce: bytes, blob: bytes, aad: bytes) -> str:
    aesgcm = AESGCM(vault_key)
    pt = aesgcm.decrypt(nonce, blob, aad)
    return pt.decode("utf-8")

# 4) Email verification token helpers
def new_email_token(exp_minutes=30):
    # TODO: this is still for dev
    token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    expires = datetime.now(timezone.utc) + timedelta(minutes=exp_minutes)
    return token, expires
