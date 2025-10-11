import uuid
from datetime import datetime, timezone
from flask_login import UserMixin
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import func
from extensions import db

def utcnow():
    return datetime.now(timezone.utc)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

    pw_hash_auth = db.Column(db.Text, nullable=False)
    kdf_salt = db.Column(db.LargeBinary, nullable=False)

    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)

    def get_id(self):
        return str(self.id)

class EmailVerificationToken(db.Model):
    __tablename__ = "email_verification_tokens"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = db.Column(db.String(512), nullable=False, index=True, unique=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    user = db.relationship("User", backref=db.backref("email_tokens", cascade="all, delete-orphan"))

class VaultEntry(db.Model):
    __tablename__ = "vault_entries"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    app_name = db.Column(db.String(255), nullable=False)
    app_login_url = db.Column(db.Text, nullable=True)

    nonce = db.Column(db.LargeBinary, nullable=False)
    enc_password = db.Column(db.LargeBinary, nullable=False)

    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(),
                           onupdate=func.now(), nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "app_name", name="uq_user_appname"),
    )

    user = db.relationship("User", backref=db.backref("vault_entries", cascade="all, delete-orphan"))
