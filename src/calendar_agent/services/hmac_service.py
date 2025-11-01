import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from app.config import get_settings


def _b64_hmac_sha256(key: bytes, message: bytes) -> str:
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def json_bytes_for_hmac(payload: dict[str, Any]) -> bytes:
    # Deterministic JSON (no spaces, sorted keys, UTF-8)
    json_str = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return json_str.encode("utf-8")


def hmac_headers_for_get(path: str) -> dict[str, str]:
    """
    Canonical (no query string; empty body for GET):
      "{timestamp}\n{nonce}\nGET\n{path_only}\n"
    """
    settings = get_settings()
    secret = settings.agent_hmac_secret
    agent_id = settings.agent_id

    if not secret:
        raise ValueError("Agent HMAC secret is required")
    if not agent_id:
        raise ValueError("Agent ID is required")

    ts = int(time.time())
    nonce = str(uuid.uuid4())
    path_only = path.split("?", 1)[0] if "?" in path else path
    canonical = f"{ts}\n{nonce}\nGET\n{path_only}\n"
    sig = _b64_hmac_sha256(secret.encode("utf-8"), canonical.encode("utf-8"))

    print(f"ts: {ts}")
    print(f"nonce: {nonce}")
    print(f"path_only: {path_only}")
    print(f"secret: {secret}")
    print(f"canonical: {canonical}")
    print(f"sig: {sig}")

    return {
        "X-Agent-Id": agent_id,
        "X-Agent-Timestamp": str(ts),
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": sig,
    }


def hmac_headers_for_post(path: str, body_bytes: bytes) -> dict[str, str]:
    """
    Canonical (no query string; body is exact bytes you will send):
      "{timestamp}\n{nonce}\nPOST\n{path_only}\n{body}"
    """
    settings = get_settings()
    secret = settings.agent_hmac_secret
    agent_id = settings.agent_id

    if not secret:
        raise ValueError("Agent HMAC secret is required")
    if not agent_id:
        raise ValueError("Agent ID is required")

    ts = int(time.time())
    nonce = str(uuid.uuid4())
    path_only = path.split("?", 1)[0] if "?" in path else path

    # IMPORTANT: body_bytes must be exactly what you send over the wire.
    canonical = (
        f"{ts}\n{nonce}\nPOST\n{path_only}\n{body_bytes.decode('utf-8') if body_bytes else ''}"
    )
    sig = _b64_hmac_sha256(secret.encode("utf-8"), canonical.encode("utf-8"))

    return {
        "X-Agent-Id": agent_id,
        "X-Agent-Timestamp": str(ts),
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": sig,
    }
