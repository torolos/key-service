from __future__ import annotations
import base64
import json
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Dict, Any, Iterable

from flask import request, abort

# ---------- Repository interface ----------
class AuthRepository(ABC):
    @abstractmethod
    def authenticate(self, client_id: str, client_secret: str) -> Optional[Dict[str, Any]]:
        """
        Return a dict like {"tenant_id": "t1", "roles": ["create","view"]} if OK, else None.
        """
        ...

# ---------- In-memory implementation (tests/dev) ----------
class InMemoryAuthRepository(AuthRepository):
    """
    accounts: { client_id: { "client_secret": "...", "tenant_id": "t", "roles": [...] } }
    """
    def __init__(self, accounts: Dict[str, Dict[str, Any]]):
        self.accounts = accounts or {}

    def authenticate(self, client_id: str, client_secret: str) -> Optional[Dict[str, Any]]:
        rec = self.accounts.get(client_id)
        if not rec:
            return None
        if rec.get("client_secret") != client_secret:
            return None
        return {"tenant_id": rec.get("tenant_id"), "roles": list(rec.get("roles", []))}

# ---------- AWS Secrets Manager implementation (prod) ----------
class AWSSecretsAuthRepository(AuthRepository):
    """
    Looks up secrets by name: f\"{prefix}/{client_id}\"
    Secret value should be a JSON object: {"client_secret":"...","tenant_id":"...","roles":["..."]}
    """
    def __init__(self, boto3_client, secret_prefix: str):
        self.client = boto3_client
        self.prefix = secret_prefix.rstrip("/")

    def authenticate(self, client_id: str, client_secret: str) -> Optional[Dict[str, Any]]:
        name = f"{self.prefix}/{client_id}"
        try:
            resp = self.client.get_secret_value(SecretId=name)
        except Exception:
            return None
        blob = resp.get("SecretString") or ""
        try:
            data = json.loads(blob)
        except Exception:
            return None
        if data.get("client_secret") != client_secret:
            return None
        return {"tenant_id": data.get("tenant_id"), "roles": list(data.get("roles", []))}

# ---------- Request parsing ----------
def _parse_basic_auth(auth_header: str) -> Optional[Tuple[str, str]]:
    try:
        scheme, b64 = auth_header.split(" ", 1)
        if scheme.lower() != "basic":
            return None
        raw = base64.b64decode(b64).decode("utf-8")
        cid, secret = raw.split(":", 1)
        return cid, secret
    except Exception:
        return None

def get_client_credentials_from_request() -> Optional[Tuple[str, str]]:
    # Prefer Authorization: Basic base64(client_id:client_secret)
    auth = request.headers.get("Authorization")
    if auth:
        p = _parse_basic_auth(auth)
        if p:
            return p
    # Fallback to explicit headers
    cid = request.headers.get("X-Client-Id")
    sec = request.headers.get("X-Client-Secret")
    if cid and sec:
        return cid, sec
    # (Optional) allow JSON body for POST
    if request.is_json:
        body = request.get_json(silent=True) or {}
        cid = body.get("client_id")
        sec = body.get("client_secret")
        if cid and sec:
            return cid, sec
    return None

# ---------- Decorator factory ----------
def make_require_roles(auth_repo: AuthRepository):
    """
    Returns a decorator @require_roles('create','admin') enforcing:
    - client_id/secret present & valid
    - tenant_id in secret matches the <tenant_id> path param (unless role 'admin_global')
    - intersection(roles, required_roles) or role 'admin' passes
    """
    def decorator(*required_roles: str):
        required = set(required_roles)
        def wrapper(fn):
            from functools import wraps
            @wraps(fn)
            def inner(*args, **kwargs):
                creds = get_client_credentials_from_request()
                if not creds:
                    abort(401, description="Missing credentials")
                client_id, client_secret = creds
                principal = auth_repo.authenticate(client_id, client_secret)
                if not principal:
                    abort(401, description="Invalid credentials")
                # tenant check unless admin_global
                path_tenant = kwargs.get("tenant_id")
                roles = set(principal.get("roles", []))
                tenant_ok = ("admin_global" in roles) or (principal.get("tenant_id") == path_tenant)
                if not tenant_ok:
                    abort(403, description="Forbidden for tenant")
                # role check
                if "admin" in roles or "admin_global" in roles or (required and roles.intersection(required)):
                    return fn(*args, **kwargs)
                abort(403, description="Insufficient role")
            return inner
        return wrapper
    return decorator
