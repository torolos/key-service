from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives import serialization
from keyservice.helpers import b64url, b64url_uint

# ---------- Strategy interface ----------
class KeyStrategy(ABC):
    name: str

    @abstractmethod
    def generate_pair(self, *, key_size: Optional[int] = None) -> Tuple[str, str, Dict[str, Any]]:
        """Return (private_pem, public_pem, meta: {alg, curve, key_size})"""

    @abstractmethod
    def to_jwk(self, public_pem: str, kid: str | int) -> Dict[str, Any]:
        """Convert public PEM to JWK dict."""

# ---------- RSA ----------
class RSAKeyStrategy(KeyStrategy):
    name = "rsa"

    def __init__(self, allowed_sizes: set[int], default_size: int = 2048):
        self.allowed_sizes = allowed_sizes
        self.default_size = default_size

    def generate_pair(self, *, key_size: Optional[int] = None):
        size = key_size or self.default_size
        if size not in self.allowed_sizes:
            raise ValueError(f"key_size must be one of {sorted(self.allowed_sizes)}")
        priv = rsa.generate_private_key(public_exponent=65537, key_size=size)
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return priv_pem, pub_pem, {"alg": "RS256", "curve": None, "key_size": size}

    def to_jwk(self, public_pem: str, kid: str | int) -> Dict[str, Any]:
        pub = serialization.load_pem_public_key(public_pem.encode())
        numbers = pub.public_numbers()
        return {"kty": "RSA", "n": b64url_uint(numbers.n), "e": b64url_uint(numbers.e),
                "use": "sig", "alg": "RS256", "kid": str(kid)}

# ---------- Ed25519 ----------
class Ed25519KeyStrategy(KeyStrategy):
    name = "ed25519"

    def generate_pair(self, *, key_size: Optional[int] = None):
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return priv_pem, pub_pem, {"alg": "EdDSA", "curve": "Ed25519", "key_size": None}

    def to_jwk(self, public_pem: str, kid: str | int) -> Dict[str, Any]:
        pub = serialization.load_pem_public_key(public_pem.encode())
        raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw),
                "use": "sig", "alg": "EdDSA", "kid": str(kid)}

# ---------- EC P-256 (ES256) ----------
class ECP256KeyStrategy(KeyStrategy):
    name = "ec-p256"

    def generate_pair(self, *, key_size: Optional[int] = None):
        priv = ec.generate_private_key(ec.SECP256R1())
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return priv_pem, pub_pem, {"alg": "ES256", "curve": "P-256", "key_size": None}

    def to_jwk(self, public_pem: str, kid: str | int) -> Dict[str, Any]:
        pub = serialization.load_pem_public_key(public_pem.encode())
        numbers = pub.public_numbers()
        x = numbers.x.to_bytes(32, "big")
        y = numbers.y.to_bytes(32, "big")
        return {"kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y),
                "use": "sig", "alg": "ES256", "kid": str(kid)}

# ---------- registry ----------
class StrategyRegistry:
    def __init__(self):
        self._by_name: dict[str, KeyStrategy] = {}

    def register(self, strategy: KeyStrategy) -> None:
        self._by_name[strategy.name] = strategy

    def get(self, name: str) -> KeyStrategy:
        try:
            return self._by_name[name]
        except KeyError:
            raise ValueError(f"Unsupported key_type '{name}'. Supported: {', '.join(sorted(self._by_name))}")

registry = StrategyRegistry()
