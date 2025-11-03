import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

_HMAC_CLOCK_SKEW = 300  # ±5 minutes


def _b64_hmac_sha256(key: bytes, message: bytes) -> str:
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def _build_canonical(
    ts: str, nonce: str, method: str, path_only: str, body_bytes: bytes | None = None
) -> str:
    # The canonical string is: "{timestamp}\n{nonce}\n{METHOD}\n{PATH}\n{BODY}"
    base_canonical = f"{ts}\n{nonce}\n{method.upper()}\n{path_only}\n"
    body_text = body_bytes.decode("utf-8") if body_bytes is not None else ""
    return f"{base_canonical}{body_text}"


def json_bytes_for_hmac(payload: dict[str, Any]) -> bytes:
    # Deterministic JSON (no spaces, sorted keys, UTF-8)
    json_str = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return json_str.encode("utf-8")


def hmac_headers_for_request(
    *,
    path: str,
    method: str,
    body_bytes: bytes,
    shared_secret: str,
    agent_id: str,
) -> dict[str, str]:
    """
    Canonical (no query string; body is exact bytes you will send):
      "{timestamp}\n{nonce}\nPOST\n{path_only}\n{body}"
    """

    if not shared_secret:
        raise ValueError("Agent HMAC secret is required")
    if not agent_id:
        raise ValueError("Agent ID is required")

    ts = int(time.time())
    ts_str = str(ts)
    nonce = str(uuid.uuid4())
    path_only = path.split("?", 1)[0] if "?" in path else path

    # IMPORTANT: body_bytes must be exactly what is being sent over the wire.
    canonical = _build_canonical(ts_str, nonce, method, path_only, body_bytes)
    sig = _b64_hmac_sha256(shared_secret.encode("utf-8"), canonical.encode("utf-8"))

    return {
        "X-Agent-Id": agent_id,
        "X-Agent-Timestamp": str(ts),
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": sig,
    }


def verify_hmac_signature(
    ts_str: str,
    nonce: str,
    method: str,
    path_only: str,
    body: str,
    provided_sig_b64: str,
    secret: str,
    now: int | None = None,
    previous_secret: str | None = None,  # optional rotation
) -> tuple[bool, str]:
    """
    Returns (is_valid, reason_if_invalid).
    """
    # Timestamp window
    try:
        ts = int(ts_str)
    except Exception:
        return False, "bad_timestamp - Invalid timestamp was provided."

    now = int(now or time.time())

    time_delta = abs(now - ts)
    if time_delta > _HMAC_CLOCK_SKEW:
        msg = (
            f"timestamp_skew - Time between server and client is {time_delta} seconds. "
            + "This could be a replay attack."
        )
        return False, msg

    body_bytes = body.encode("utf-8") if body else None
    canonical = _build_canonical(ts_str, nonce, method, path_only, body_bytes)
    expected = _b64_hmac_sha256(secret.encode("utf-8"), canonical.encode("utf-8"))

    if hmac.compare_digest(expected, provided_sig_b64):
        return True, ""

    if previous_secret:  # optional graceful rotation
        expected_prev = _b64_hmac_sha256(previous_secret.encode(), canonical.encode())
        if hmac.compare_digest(expected_prev, provided_sig_b64):
            return True, ""

    return False, "bad_signature"
