import base64
from keyservice.strategies import RSAKeyStrategy, Ed25519KeyStrategy, ECP256KeyStrategy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def test_rsa_strategy_generate_and_jwk():
    s = RSAKeyStrategy(allowed_sizes={2048,3072,4096}, default_size=2048)
    priv_pem, pub_pem, meta = s.generate_pair()
    assert meta["alg"] == "RS256" and meta["curve"] is None and meta["key_size"] == 2048

    # public key loads
    pub = serialization.load_pem_public_key(pub_pem.encode())
    assert isinstance(pub, rsa.RSAPublicKey)
    numbers = pub.public_numbers()

    jwk = s.to_jwk(pub_pem, kid="k1")
    assert jwk["kty"] == "RSA" and jwk["alg"] == "RS256" and jwk["kid"] == "k1"
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    assert n == numbers.n and e == numbers.e

def test_ed25519_strategy_generate_and_jwk():
    s = Ed25519KeyStrategy()
    priv_pem, pub_pem, meta = s.generate_pair()
    assert meta["alg"] == "EdDSA" and meta["curve"] == "Ed25519" and meta["key_size"] is None

    pub = serialization.load_pem_public_key(pub_pem.encode())
    assert isinstance(pub, ed25519.Ed25519PublicKey)
    raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    jwk = s.to_jwk(pub_pem, kid=7)
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and jwk["kid"] == "7"
    x = b64url_decode(jwk["x"])
    assert len(x) == 32 and x == raw  # 32-byte raw public key

def test_ec_p256_strategy_generate_and_jwk():
    s = ECP256KeyStrategy()
    priv_pem, pub_pem, meta = s.generate_pair()
    assert meta["alg"] == "ES256" and meta["curve"] == "P-256"

    pub = serialization.load_pem_public_key(pub_pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    nums = pub.public_numbers()
    x_bytes = nums.x.to_bytes(32, "big")
    y_bytes = nums.y.to_bytes(32, "big")

    jwk = s.to_jwk(pub_pem, kid=55)
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256" and jwk["kid"] == "55"
    assert b64url_decode(jwk["x"]) == x_bytes
    assert b64url_decode(jwk["y"]) == y_bytes
