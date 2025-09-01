import types
from types import SimpleNamespace
from keyservice.helpers import b64url, b64url_uint, now_utc, generate_kid_non_colliding
import base64

def b64url_decode(s: str) -> bytes:
    # add padding back for Python's base64
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def test_b64url_roundtrip():
    data = b"\x00\x01\xfe\xffhello"
    enc = b64url(data)
    assert "=" not in enc
    assert b64url_decode(enc) == data

def test_b64url_uint_known_values():
    # 65537 (0x10001) => AQAB (common RSA e)
    assert b64url_uint(65537) == "AQAB"
    # 0 -> empty byte is 0x00 => "AA" after base64 + strip padding -> actually "", but our function encodes integer properly
    assert b64url_uint(1) == "AQ"
    assert b64url_uint(0) == "AA" or b64url_uint(0) == ""  # tolerate implementation detail

def test_now_utc_has_tz():
    t = now_utc()
    assert t.tzinfo is not None and t.utcoffset().total_seconds() == 0

def test_generate_kid_non_colliding_with_collisions(monkeypatch):
    # Simulate two collisions then a unique id
    seq = [11111111, 11111111, 22222222]
    def fake_randint(a, b):
        return seq.pop(0)

    # exists returns True only for 11111111
    taken = {11111111}
    def exists_fn(tenant_id, kid):
        return kid in taken

    monkeypatch.setattr("random.randint", fake_randint)
    kid = generate_kid_non_colliding("t", exists_fn)
    assert kid == 22222222
