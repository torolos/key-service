from datetime import datetime, timedelta, timezone
import base64
import pytest

from keyservice.app import create_app
from keyservice.extensions import db
from keyservice.models import KeyPair

def basic(cid, secret):
    token = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {token}"}

class TestConfig:
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEFAULT_KEY_TYPE = "rsa"
    DEFAULT_KEY_SIZE = 2048
    DEFAULT_DURATION_DAYS = 90
    ALLOWED_RSA_SIZES = {2048, 3072, 4096}
    STORAGE_BACKEND = "sqlalchemy"
    AUTH_BACKEND = "inmemory"
    # Accounts per-tenant with roles
    INMEM_ACCOUNTS = {
        "creator_a": {"client_secret":"sa","tenant_id":"a","roles":["create","view"]},
        "creator_b": {"client_secret":"sb","tenant_id":"b","roles":["create","view"]},
        "creator_c": {"client_secret":"sc","tenant_id":"c","roles":["create","view"]},

        "creator_d":    {"client_secret":"sdc","tenant_id":"d","roles":["create","view"]},     # NEW
        "creator_list": {"client_secret":"slc","tenant_id":"list","roles":["create","view"]}, # NEW
        "creator_rot": {"client_secret":"src","tenant_id":"rot","roles":["create","view"]},

        "rot_user":  {"client_secret":"sr","tenant_id":"rot","roles":["rotate","view"]},
        "dis_user":  {"client_secret":"sd","tenant_id":"d","roles":["disable","view"]},
        "lister":    {"client_secret":"sl","tenant_id":"list","roles":["view"]},
        "admin_a":   {"client_secret":"sa2","tenant_id":"a","roles":["admin","view","create","rotate","disable"]},
    }

    LIST_DEFAULT_LIMIT = 50
    LIST_MAX_LIMIT = 200

@pytest.fixture()
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
    return app

@pytest.fixture()
def client(app):
    return app.test_client()

def test_missing_auth_rejected(client):
    r = client.post("/tenants/a/keys", json={})
    assert r.status_code == 401

def test_wrong_tenant_forbidden(client):
    # credentials for tenant 'a' hitting tenant 'b'
    r = client.post("/tenants/b/keys", json={}, headers=basic("creator_a","sa"))
    assert r.status_code == 403

def test_create_rsa_default(client):
    r = client.post("/tenants/a/keys", json={}, headers=basic("creator_a","sa"))
    assert r.status_code == 201
    d = r.get_json()
    assert d["key_type"] == "rsa" and d["key_size"] == 2048

def test_create_ed25519_and_jwks(client):
    r = client.post("/tenants/b/keys", json={"key_type": "ed25519", "key_id": 7}, headers=basic("creator_b","sb"))
    assert r.status_code == 201
    jwks = client.get("/tenants/b/.well-known/jwks.json").get_json()
    assert len(jwks["keys"]) == 1 and jwks["keys"][0]["kty"] == "OKP" and jwks["keys"][0]["kid"] == "7"

def test_create_ec_p256_and_jwks(client):
    r = client.post("/tenants/c/keys", json={"key_type": "ec-p256", "key_id": 55}, headers=basic("creator_c","sc"))
    assert r.status_code == 201
    jwks = client.get("/tenants/c/.well-known/jwks.json").get_json()
    j = jwks["keys"][0]
    assert j["kty"] == "EC" and j["crv"] == "P-256" and j["kid"] == "55"

def test_invalid_type_and_invalid_size(client):
    r1 = client.post("/tenants/a/keys", json={"key_type": "dsa"}, headers=basic("creator_a","sa"))
    assert r1.status_code == 400
    r2 = client.post("/tenants/a/keys", json={"key_type": "rsa", "key_size": 1234}, headers=basic("creator_a","sa"))
    assert r2.status_code == 400

def test_rotate_and_deactivate_previous(client):
    # Create with a creator (rotate-only user cannot call create_key)
    client.post("/tenants/rot/keys", json={"key_id": 10}, headers=basic("creator_rot","src"))
    client.post("/tenants/rot/keys/rotate", json={"deactivate_previous": True, "key_id": 11}, headers=basic("rot_user","sr"))
    jwks = client.get("/tenants/rot/.well-known/jwks.json").get_json()
    assert len(jwks["keys"]) == 1 and jwks["keys"][0]["kid"] == "11"

def test_disable_requires_role(client):
    # Create with a creator (disable-only user cannot call create_key)
    r = client.post("/tenants/d/keys", json={}, headers=basic("creator_d","sdc"))
    kid = r.get_json()["key_id"]
    # viewer cannot disable
    r_forbidden = client.post(f"/tenants/d/keys/{kid}/disable", headers=basic("lister","sl"))
    assert r_forbidden.status_code == 403
    # dis_user can disable
    d = client.post(f"/tenants/d/keys/{kid}/disable", headers=basic("dis_user","sd"))
    assert d.status_code == 200
    jwks = client.get("/tenants/d/.well-known/jwks.json").get_json()
    assert len(jwks["keys"]) == 0

def test_admin_list_filters_and_pagination(client, app):
    # Create with a creator (viewer cannot call create_key)
    r1 = client.post("/tenants/list/keys", json={"key_id": 1}, headers=basic("creator_list","slc"))
    # add expired & inactive directly
    with app.app_context():
        active = KeyPair.query.filter_by(tenant_id="list", key_id=r1.get_json()["key_id"]).first()
        from keyservice.extensions import db as _db
        expired = KeyPair(
            tenant_id="list", key_id=2, key_type="rsa",
            private_key_pem=active.private_key_pem, public_key_pem=active.public_key_pem,
            key_size=2048,
            created_at=datetime.now(timezone.utc) - timedelta(days=10),
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            active=True,
        )
        inactive = KeyPair(
            tenant_id="list", key_id=3, key_type="rsa",
            private_key_pem=active.private_key_pem, public_key_pem=active.public_key_pem,
            key_size=2048,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            active=False,
        )
        _db.session.add_all([expired, inactive]); _db.session.commit()

    # Default: unexpired (active+inactive)
    q1 = client.get("/tenants/list/keys", headers=basic("lister","sl")).get_json()
    assert q1["total"] == 2 and len(q1["items"]) == 2

    # Include expired
    q2 = client.get("/tenants/list/keys?include_expired=true", headers=basic("lister","sl")).get_json()
    assert q2["total"] == 3

    # Only inactive
    q3 = client.get("/tenants/list/keys?active=false&include_expired=true", headers=basic("lister","sl")).get_json()
    assert q3["total"] == 1 and q3["items"][0]["key_id"] == 3
