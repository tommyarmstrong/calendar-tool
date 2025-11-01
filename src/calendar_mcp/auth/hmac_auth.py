import base64
import hashlib
import hmac
import time

HMAC_CLOCK_SKEW = 300  # ±5 minutes


def _b64_hmac_sha256(key: bytes, message: bytes) -> str:
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def build_canonical(ts: str, nonce: str, method: str, path_only: str, body: str) -> str:
    # The canonical string is: "{timestamp}\n{nonce}\n{METHOD}\n{PATH}\n{BODY}"
    return f"{ts}\n{nonce}\n{method.upper()}\n{path_only}\n{body}"


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
        return False, "bad_timestamp"

    now = int(now or time.time())
    print(f"now: {now}")
    print(f"ts: {ts}")
    print(f"HMAC_CLOCK_SKEW: {HMAC_CLOCK_SKEW}")
    print(f"abs(now - ts): {abs(now - ts)}")
    if abs(now - ts) > HMAC_CLOCK_SKEW:
        return False, "timestamp_skew"

    canonical = build_canonical(ts_str, nonce, method, path_only, body)
    expected = _b64_hmac_sha256(secret.encode(), canonical.encode())

    print(f"canonical: {canonical}")
    print(f"expected: {expected}")
    print(f"provided_sig_b64: {provided_sig_b64}")

    if hmac.compare_digest(expected, provided_sig_b64):
        return True, ""

    if previous_secret:  # optional graceful rotation
        expected_prev = _b64_hmac_sha256(previous_secret.encode(), canonical.encode())
        if hmac.compare_digest(expected_prev, provided_sig_b64):
            return True, ""

    return False, "bad_signature"
