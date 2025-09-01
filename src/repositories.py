from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterable, Optional, Tuple
from datetime import datetime
from extensions import db
from models import KeyPair

# ---------- Repository interface ----------
class KeyRepository(ABC):
    @abstractmethod
    def exists(self, tenant_id: str, key_id: int) -> bool: ...
    @abstractmethod
    def create(self, kp: KeyPair) -> KeyPair: ...
    @abstractmethod
    def deactivate_others(self, tenant_id: str, exclude_key_id: int, now: datetime) -> int: ...
    @abstractmethod
    def get_active_unexpired(self, tenant_id: str, now: datetime) -> list[KeyPair]: ...
    @abstractmethod
    def get_one(self, tenant_id: str, key_id: int) -> Optional[KeyPair]: ...
    @abstractmethod
    def save(self, kp: KeyPair) -> None: ...
    @abstractmethod
    def list_keys(
        self,
        tenant_id: str,
        *,
        active: Optional[bool],
        include_expired: bool,
        now: datetime,
        limit: int,
        offset: int
    ) -> Tuple[list[KeyPair], int]: ...

# ---------- SQLAlchemy implementation ----------
class SQLAlchemyKeyRepository(KeyRepository):
    def exists(self, tenant_id: str, key_id: int) -> bool:
        return db.session.query(KeyPair.id).filter_by(tenant_id=tenant_id, key_id=key_id).first() is not None

    def create(self, kp: KeyPair) -> KeyPair:
        db.session.add(kp)
        db.session.commit()
        return kp

    def deactivate_others(self, tenant_id: str, exclude_key_id: int, now: datetime) -> int:
        q = KeyPair.query.filter(
            KeyPair.tenant_id == tenant_id,
            KeyPair.active.is_(True),
            KeyPair.expires_at > now,
            KeyPair.key_id != exclude_key_id,
        )
        count = q.update({KeyPair.active: False}, synchronize_session=False)
        db.session.commit()
        return count

    def get_active_unexpired(self, tenant_id: str, now: datetime) -> list[KeyPair]:
        return (KeyPair.query
                .filter(KeyPair.tenant_id == tenant_id,
                        KeyPair.active.is_(True),
                        KeyPair.expires_at > now)
                .order_by(KeyPair.created_at.desc())
                .all())

    def get_one(self, tenant_id: str, key_id: int) -> Optional[KeyPair]:
        return KeyPair.query.filter_by(tenant_id=tenant_id, key_id=key_id).first()

    def save(self, kp: KeyPair) -> None:
        db.session.add(kp)
        db.session.commit()

    def list_keys(self, tenant_id: str, *, active: Optional[bool], include_expired: bool,
                  now: datetime, limit: int, offset: int) -> Tuple[list[KeyPair], int]:
        q = KeyPair.query.filter(KeyPair.tenant_id == tenant_id)
        if active is not None:
            q = q.filter(KeyPair.active.is_(active))
        if not include_expired:
            q = q.filter(KeyPair.expires_at > now)
        total = q.count()
        rows = (q.order_by(KeyPair.created_at.desc())
                 .offset(offset)
                 .limit(limit)
                 .all())
        return rows, total

# Future: DynamoDBKeyRepository, PsycopgKeyRepository, etc.
