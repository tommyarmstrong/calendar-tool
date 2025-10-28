import json

from cryptography.fernet import Fernet
from redis import Redis

from app.config import GOOGLE_TOKEN_TTL, settings

redis = Redis.from_url(settings.redis_url, decode_responses=True)

# Stage-1: single local user key; Stage-2/3 key by (provider, team, user)
USER_KEY = "user:local"


# Encryption setup
def _get_encryption_key() -> bytes:
    """Get or generate encryption key for token encryption."""
    key = settings.calendar_token_encryption_key
    if not key:
        raise ValueError("CALENDAR_TOKEN_ENCRYPTION_KEY is not set")

    # Type assertion: str.encode() returns bytes
    result = key.encode()
    assert isinstance(result, bytes)
    return result


def _get_fernet() -> Fernet:
    """Get Fernet cipher instance for encryption/decryption."""
    return Fernet(_get_encryption_key())


def encrypt_sensitive_fields(
    tokens: dict[str, str | list[str] | None],
) -> dict[str, str | list[str] | None]:
    """
    Encrypt sensitive token fields before storing in Redis.

    Sensitive fields: token, refresh_token, client_secret
    Non-sensitive fields: token_uri, client_id, scopes, expiry
    """
    if not tokens:
        return tokens

    fernet = _get_fernet()
    encrypted_tokens = tokens.copy()

    # Encrypt sensitive fields
    sensitive_fields = ["token", "refresh_token", "client_secret"]
    for field in sensitive_fields:
        if field in tokens and tokens[field]:
            try:
                encrypted_value = fernet.encrypt(str(tokens[field]).encode())
                encrypted_tokens[field] = encrypted_value.decode()
            except Exception:
                # Keep original value if encryption fails
                encrypted_tokens[field] = tokens[field]

    return encrypted_tokens


def decrypt_sensitive_fields(tokens: dict[str, str | None]) -> dict[str, str | None]:
    """
    Decrypt sensitive token fields after loading from Redis.

    Sensitive fields: token, refresh_token, client_secret
    Non-sensitive fields: token_uri, client_id, scopes, expiry
    """
    if not tokens:
        return tokens

    fernet = _get_fernet()
    decrypted_tokens = tokens.copy()

    # Decrypt sensitive fields
    sensitive_fields = ["token", "refresh_token", "client_secret"]
    for field in sensitive_fields:
        if field in tokens and tokens[field]:
            try:
                decrypted_value = fernet.decrypt(str(tokens[field]).encode())
                decrypted_tokens[field] = decrypted_value.decode()
            except Exception:
                # Keep original value if decryption fails (might be unencrypted)
                decrypted_tokens[field] = tokens[field]

    return decrypted_tokens


def save_tokens(tokens: dict[str, str | list[str] | None]) -> None:
    # Encrypt sensitive fields before storing
    encrypted_tokens = encrypt_sensitive_fields(tokens)

    redis.hset(USER_KEY, mapping={"tokens": json.dumps(encrypted_tokens)})
    redis.expire(USER_KEY, GOOGLE_TOKEN_TTL)


def load_tokens() -> dict[str, str | None] | None:
    raw = redis.hget(USER_KEY, "tokens")
    if not raw:
        return None

    # Decrypt sensitive fields
    encrypted_tokens = json.loads(str(raw))
    return decrypt_sensitive_fields(encrypted_tokens)


def purge_tokens() -> None:
    redis.delete(USER_KEY)


def save_timezone(tz: str) -> None:
    redis.hset(USER_KEY, "tz", tz)


def set_idempotency(key: str, ttl_sec: int = 600) -> None:
    redis.setex(f"idem:{key}", ttl_sec, "1")


def has_idempotency(key: str) -> bool:
    return redis.exists(f"idem:{key}") == 1
