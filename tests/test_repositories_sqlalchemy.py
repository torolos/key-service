import pytest
from datetime import timedelta
from keyservice.config import Config
from keyservice.extensions import db
from keyservice.models import KeyPair
from keyservice.repositories import SQLAlchemyKeyRepository
from keyservice.helpers import now_utc

class TestConfig(Config):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    STORAGE_BACKEND = "sqlalchemy"

@pytest.fixture()
def app():
    # Minimal app factory inline (matches your existing create_app style)
    from flask import Flask
    app = Flask(__name__)
    app.config.from_object(TestConfig)
    db.init_app(app)
    with app.app_context():
        db.create_all()
    yield app

@pytest.fixture()
def repo(app):
    return SQLAlchemyKeyRepository()

def make_kp(tenant="t", kid=1, active=True, expire_in_days=30, key_type="rsa"):
    now = now_utc()
    return KeyPair(
        tenant_id=tenant, key_id=kid, key_type=key_type, curve=None,
        private_key_pem="priv", public_key_pem="pub", key_size=2048 if key_type=="rsa" else None,
        created_at=now, expires_at=now + timedelta(days=expire_in_days), active=active
    )

def test_exists_create_get_one(repo, app):
    with app.app_context():
        assert not repo.exists("t", 1)
        kp = make_kp("t", 1)
        repo.create(kp)
        assert repo.exists("t", 1)
        found = repo.get_one("t", 1)
        assert isinstance(found, KeyPair) and found.key_id == 1

def test_get_active_unexpired_and_deactivate(repo, app):
    with app.app_context():
        now = now_utc()
        repo.create(make_kp("t", 1, active=True, expire_in_days=30))
        repo.create(make_kp("t", 2, active=True, expire_in_days=-1))   # expired
        repo.create(make_kp("t", 3, active=False, expire_in_days=30))  # inactive

        active_unexpired = repo.get_active_unexpired("t", now)
        assert [k.key_id for k in active_unexpired] == [1]

        # deactivate others (none besides key 1)
        changed = repo.deactivate_others("t", exclude_key_id=1, now=now)
        assert changed == 0

def test_list_and_save(repo, app):
    with app.app_context():
        now = now_utc()
        repo.create(make_kp("t", 1, active=True, expire_in_days=30))
        repo.create(make_kp("t", 2, active=True, expire_in_days=-1))  # expired
        repo.create(make_kp("t", 3, active=False, expire_in_days=30))

        rows, total = repo.list_keys("t", active=None, include_expired=False, now=now, limit=50, offset=0)
        # unexpired keys: ids 1 and 3
        assert total == 2
        assert sorted([r.key_id for r in rows]) == [1,3]

        # Only inactive, include expired
        rows, total = repo.list_keys("t", active=False, include_expired=True, now=now, limit=50, offset=0)
        assert total == 1 and rows[0].key_id == 3

        # Save: deactivate id=1
        one = repo.get_one("t", 1)
        one.active = False
        repo.save(one)
        assert repo.get_one("t", 1).active is False
