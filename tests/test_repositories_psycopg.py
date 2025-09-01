import os
import pytest
from datetime import timedelta
from types import SimpleNamespace
from keyservice.helpers import now_utc
try:
    from keyservice.repositories_psycopg import PsycopgKeyRepository, DDL
    import psycopg
except Exception:  # pragma: no cover
    PsycopgKeyRepository = None

RUN_PG = os.getenv("RUN_PG_TESTS") == "1" or os.getenv("POSTGRES_DSN") is not None
PG_DSN = os.getenv("POSTGRES_DSN", "postgresql://postgres:postgres@localhost:5432/jwks")

pytestmark = pytest.mark.skipif(not RUN_PG or PsycopgKeyRepository is None, reason="Postgres DSN not set or psycopg not available")

@pytest.fixture(autouse=True)
def clean_db():
    with psycopg.connect(PG_DSN, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(DDL)
        cur.execute("TRUNCATE TABLE key_pairs RESTART IDENTITY;")
    yield

@pytest.fixture()
def repo():
    return PsycopgKeyRepository(PG_DSN)

def make_obj(tenant="t", kid=1, active=True, expire_in_days=30, key_type="rsa"):
    now = now_utc()
    return SimpleNamespace(
        tenant_id=tenant, key_id=kid, key_type=key_type, curve=None,
        private_key_pem="priv", public_key_pem="pub",
        key_size=2048 if key_type == "rsa" else None,
        created_at=now, expires_at=now + timedelta(days=expire_in_days),
        active=active
    )

def test_exists_create_get_one(repo):
    assert repo.exists("t", 1) is False
    repo.create(make_obj("t", 1))
    assert repo.exists("t", 1) is True
    row = repo.get_one("t", 1)
    assert row is not None and row["key_id"] == 1 and row["tenant_id"] == "t"

def test_get_active_unexpired_and_deactivate(repo):
    now = now_utc()
    repo.create(make_obj("t", 1, True, 30))
    repo.create(make_obj("t", 2, True, -1))   # expired
    repo.create(make_obj("t", 3, False, 30))  # inactive

    rows = repo.get_active_unexpired("t", now)
    assert [r["key_id"] for r in rows] == [1]

    changed = repo.deactivate_others("t", exclude_key_id=1, now=now)
    assert changed == 0

def test_list_and_save(repo):
    now = now_utc()
    repo.create(make_obj("t", 1, True, 30))
    repo.create(make_obj("t", 2, True, -1))
    repo.create(make_obj("t", 3, False, 30))

    rows, total = repo.list_keys("t", active=None, include_expired=False, now=now, limit=50, offset=0)
    assert total == 2
    assert sorted([r["key_id"] for r in rows]) == [1,3]

    # Only inactive, include expired
    rows, total = repo.list_keys("t", active=False, include_expired=True, now=now, limit=50, offset=0)
    assert total == 1 and rows[0]["key_id"] == 3

    # Save: deactivate id=1
    obj = make_obj("t", 1, False, 30)
    repo.save(obj)
    row = repo.get_one("t", 1)
    assert row["active"] is False
