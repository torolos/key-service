from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from flask import Flask, jsonify, request, abort
from config import Config
from extensions import db
from models import KeyPair
from helpers import now_utc, generate_kid_non_colliding
from strategies import registry, RSAKeyStrategy, Ed25519KeyStrategy, ECP256KeyStrategy
from repositories import KeyRepository, SQLAlchemyKeyRepository
from repositories_psycopg import PsycopgKeyRepository

# NEW
from auth import InMemoryAuthRepository, AWSSecretsAuthRepository, make_require_roles

def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)

    # Strategies
    registry.register(RSAKeyStrategy(allowed_sizes=app.config["ALLOWED_RSA_SIZES"],
                                     default_size=app.config["DEFAULT_KEY_SIZE"]))
    registry.register(Ed25519KeyStrategy())
    registry.register(ECP256KeyStrategy())

    # Persistence repo
    storage = app.config.get("STORAGE_BACKEND", "sqlalchemy")
    if storage == "sqlalchemy":
        repo: KeyRepository = SQLAlchemyKeyRepository()
        with app.app_context():
            db.create_all()
    elif storage == "psycopg":
        # Psycopg repo manages its own table DDL if missing
        dsn = app.config["POSTGRES_DSN"]
        repo = PsycopgKeyRepository(dsn)
    else:
        raise RuntimeError(f"Unsupported STORAGE_BACKEND={storage}")

    # ---- Auth repo selection
    auth_backend = app.config.get("AUTH_BACKEND", "inmemory")
    if auth_backend == "aws":
        import boto3
        sm = boto3.client("secretsmanager", region_name=app.config["AWS_REGION"])
        auth_repo = AWSSecretsAuthRepository(sm, app.config["AWS_SECRETS_PREFIX"])
    elif auth_backend == "inmemory":
        auth_repo = InMemoryAuthRepository(app.config.get("INMEM_ACCOUNTS", {}))
    else:
        raise RuntimeError(f"Unsupported AUTH_BACKEND={auth_backend}")

    require_roles = make_require_roles(auth_repo)

    # ---------------- routes ----------------
    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/tenants/<tenant_id>/keys")
    @require_roles("create", "admin")   # client must have one of these roles (or admin_global)
    def create_key(tenant_id: str):
        payload = request.get_json(silent=True) or {}
        key_type = (payload.get("key_type") or app.config["DEFAULT_KEY_TYPE"]).lower()
        key_size = payload.get("key_size")
        duration_days = int(payload.get("duration_days", app.config["DEFAULT_DURATION_DAYS"]))

        # key_id
        if payload.get("key_id") is None:
            kid = generate_kid_non_colliding(tenant_id, repo.exists)
        else:
            kid = payload["key_id"]
            if not isinstance(kid, int):
                abort(400, description="key_id must be an integer")
            if repo.exists(tenant_id, kid):
                abort(409, description="A key with this key_id already exists for this tenant")
        if duration_days <= 0:
            abort(400, description="duration_days must be positive")

        # strategy
        try:
            strategy = registry.get(key_type)
            priv_pem, pub_pem, meta = strategy.generate_pair(key_size=key_size)
        except ValueError as e:
            abort(400, description=str(e))

        now = now_utc()
        kp = KeyPair(
            tenant_id=tenant_id, key_id=kid, key_type=key_type, curve=meta.get("curve"),
            private_key_pem=priv_pem, public_key_pem=pub_pem, key_size=meta.get("key_size"),
            created_at=now, expires_at=now + timedelta(days=duration_days), active=True
        )
        repo.create(kp)
        return jsonify({
            "tenant_id": tenant_id, "key_id": kid, "key_type": key_type,
            "key_size": meta.get("key_size"), "curve": meta.get("curve"), "alg": meta.get("alg"),
            "created_at": kp.created_at.isoformat(), "expires_at": kp.expires_at.isoformat(), "active": kp.active
        }), 201

    @app.post("/tenants/<tenant_id>/keys/rotate")
    @require_roles("rotate", "admin")
    def rotate_key(tenant_id: str):
        payload = request.get_json(silent=True) or {}
        deactivate_prev = bool(payload.get("deactivate_previous", False))
        # Reuse create_key impl without re-checking auth
        resp = create_key.__wrapped__(tenant_id)  # type: ignore[attr-defined]
        new_kid = resp[0].get_json()["key_id"]
        if deactivate_prev:
            repo.deactivate_others(tenant_id, new_kid, now_utc())
        return resp

    @app.post("/tenants/<tenant_id>/keys/<int:key_id>/disable")
    @require_roles("disable", "admin")
    def disable_key(tenant_id: str, key_id: int):
        kp = repo.get_one(tenant_id, key_id)
        if not kp:
            abort(404, description="Key not found")
        kp.active = False
        repo.save(kp)
        return jsonify({"tenant_id": tenant_id, "key_id": key_id, "active": False})

    @app.get("/tenants/<tenant_id>/.well-known/jwks.json")
    # public exposure of active keys is often public; keep unauthenticated by default.
    def jwks(tenant_id: str):
        keys = repo.get_active_unexpired(tenant_id, now_utc())
        jwks_keys = [registry.get(k.key_type).to_jwk(k.public_key_pem, k.key_id) for k in keys]
        return jsonify({"keys": jwks_keys})

    @app.get("/tenants/<tenant_id>/keys")
    @require_roles("view", "admin")   # admin list endpoint
    def list_keys(tenant_id: str):
        active_param = request.args.get("active")
        active = None if active_param is None else active_param.lower() == "true"
        include_expired = request.args.get("include_expired", "false").lower() == "true"
        limit = min(int(request.args.get("limit", app.config["LIST_DEFAULT_LIMIT"])), app.config["LIST_MAX_LIMIT"])
        offset = int(request.args.get("offset", 0))

        rows, total = repo.list_keys(tenant_id, active=active, include_expired=include_expired,
                                     now=now_utc(), limit=limit, offset=offset)
        items = [{
            "tenant_id": r.tenant_id, "key_id": r.key_id, "key_type": r.key_type, "curve": r.curve,
            "key_size": r.key_size, "created_at": r.created_at.isoformat(),
            "expires_at": r.expires_at.isoformat(), "active": r.active
        } for r in rows]
        return jsonify({"total": total, "items": items, "limit": limit, "offset": offset})

    return app

app = create_app()
