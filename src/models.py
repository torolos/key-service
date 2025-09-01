from datetime import datetime, timezone
from sqlalchemy import UniqueConstraint
from extensions import db

class KeyPair(db.Model):
    __tablename__ = "key_pairs"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(255), nullable=False, index=True)
    key_id = db.Column(db.Integer, nullable=False)

    key_type = db.Column(db.String(32), nullable=False, default="rsa")  # 'rsa' | 'ed25519' | 'ec-p256'
    curve = db.Column(db.String(32), nullable=True)  # 'Ed25519', 'P-256' etc.

    private_key_pem = db.Column(db.Text, nullable=False)
    public_key_pem  = db.Column(db.Text, nullable=False)

    key_size   = db.Column(db.Integer, nullable=True)  # RSA only
    created_at = db.Column(db.DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    active     = db.Column(db.Boolean, nullable=False, default=True)

    __table_args__ = (UniqueConstraint("tenant_id", "key_id", name="uq_tenant_kid"),)

    @property
    def is_active_now(self) -> bool:
        return self.active and self.expires_at > datetime.now(timezone.utc)
