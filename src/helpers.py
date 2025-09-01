import base64
import random
from datetime import datetime, timezone

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_uint(n: int) -> str:
    l = (n.bit_length() + 7) // 8
    return b64url(n.to_bytes(l, "big"))

def now_utc():
    return datetime.now(timezone.utc)

def generate_kid_non_colliding(tenant_id: str, exists_fn, attempts: int = 24) -> int:
    """
    exists_fn(tenant_id: str, kid: int) -> bool
    """
    for _ in range(attempts):
        cand = random.randint(10_000_000, 9_999_999_999)
        if not exists_fn(tenant_id, cand):
            return cand
    raise RuntimeError("Failed to generate a unique key_id; try again.")
