from __future__ import annotations
from typing import Optional, Tuple, List
from datetime import datetime
import psycopg
from psycopg.rows import dict_row

from repositories import KeyRepository
# We avoid importing SQLAlchemy model here; we return dicts & build KeyPair-like dicts.

DDL = """
CREATE TABLE IF NOT EXISTS key_pairs (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    key_id BIGINT NOT NULL,
    key_type VARCHAR(32) NOT NULL DEFAULT 'rsa',
    curve VARCHAR(32),
    private_key_pem TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    key_size INT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT uq_tenant_kid UNIQUE (tenant_id, key_id)
);
CREATE INDEX IF NOT EXISTS ix_key_pairs_tenant ON key_pairs(tenant_id);
"""

class PsycopgKeyRepository(KeyRepository):
    """
    A pure-psycopg implementation of KeyRepository.
    NOTE: We return plain dicts with fields like the SQLAlchemy model.
          The Flask routes only need these fields; no ORM required.
    """
    def __init__(self, dsn: str):
        # Use a single connection with autocommit for simplicity.
        self.conn = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
        with self.conn.cursor() as cur:
            cur.execute(DDL)

    # --- helpers ---
    @staticmethod
    def _row_to_dict(row: dict) -> dict:
        # Already dict_row; ensure snake_case fields match app expectations.
        return row

    # --- interface methods ---
    def exists(self, tenant_id: str, key_id: int) -> bool:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM key_pairs WHERE tenant_id = %s AND key_id = %s LIMIT 1;",
                (tenant_id, key_id),
            )
            return cur.fetchone() is not None

    def create(self, kp) -> dict:
        # kp is an object (SQLAlchemy model in app), but we only read its attributes.
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO key_pairs
                (tenant_id, key_id, key_type, curve, private_key_pem, public_key_pem,
                 key_size, created_at, expires_at, active)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING *;
                """,
                (
                    kp.tenant_id, kp.key_id, kp.key_type, kp.curve, kp.private_key_pem,
                    kp.public_key_pem, kp.key_size, kp.created_at, kp.expires_at, kp.active
                ),
            )
            row = cur.fetchone()
            return self._row_to_dict(row)

    def deactivate_others(self, tenant_id: str, exclude_key_id: int, now: datetime) -> int:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                UPDATE key_pairs
                   SET active = FALSE
                 WHERE tenant_id = %s
                   AND active = TRUE
                   AND expires_at > %s
                   AND key_id <> %s;
                """,
                (tenant_id, now, exclude_key_id),
            )
            return cur.rowcount

    def get_active_unexpired(self, tenant_id: str, now: datetime) -> List[dict]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM key_pairs
                 WHERE tenant_id = %s
                   AND active = TRUE
                   AND expires_at > %s
                 ORDER BY created_at DESC;
                """,
                (tenant_id, now),
            )
            rows = cur.fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_one(self, tenant_id: str, key_id: int) -> Optional[dict]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM key_pairs WHERE tenant_id = %s AND key_id = %s;",
                (tenant_id, key_id),
            )
            row = cur.fetchone()
            return self._row_to_dict(row) if row else None

    def save(self, kp) -> None:
        # kp may be a dict or ORM object; read attributes safely
        tenant_id = getattr(kp, "tenant_id", kp["tenant_id"])
        key_id = getattr(kp, "key_id", kp["key_id"])
        active = getattr(kp, "active", kp["active"])
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE key_pairs SET active = %s WHERE tenant_id = %s AND key_id = %s;",
                (active, tenant_id, key_id),
            )

    def list_keys(
        self,
        tenant_id: str,
        *,
        active: Optional[bool],
        include_expired: bool,
        now: datetime,
        limit: int,
        offset: int,
    ) -> Tuple[list[dict], int]:
        wheres = ["tenant_id = %s"]
        params = [tenant_id]

        if active is not None:
            wheres.append("active = %s")
            params.append(active)
        if not include_expired:
            wheres.append("expires_at > %s")
            params.append(now)

        where_sql = " AND ".join(wheres)

        # total count
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS c FROM key_pairs WHERE {where_sql};", tuple(params))
            total = cur.fetchone()["c"]

        # items
        with self.conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT * FROM key_pairs
                 WHERE {where_sql}
                 ORDER BY created_at DESC
                 OFFSET %s LIMIT %s;
                """,
                (*params, offset, limit),
            )
            rows = cur.fetchall()

        return [self._row_to_dict(r) for r in rows], int(total)
