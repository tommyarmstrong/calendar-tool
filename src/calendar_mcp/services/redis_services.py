import json
from datetime import UTC, datetime

from cryptography.fernet import Fernet
from redis import Redis

from app.config import settings

redis = Redis.from_url(settings.redis_url, decode_responses=True)

# Stage-1: single local user key; Stage-2/3 key by (provider, team, user)
USER_KEY = "user:local"


# Encryption setup
def _get_encryption_key() -> bytes:
    """Get or generate encryption key for token encryption."""
    key = settings.calendar_token_encryption_key
    print(f"Encryption key: {key}")
    if not key:
        raise ValueError("CALENDAR_TOKEN_ENCRYPTION_KEY is not set")

    # Type assertion: str.encode() returns bytes
    result = key.encode()
    assert isinstance(result, bytes)
    return result


def _get_fernet() -> Fernet:
    """Get Fernet cipher instance for encryption/decryption."""
    return Fernet(_get_encryption_key())


def encrypt_sensitive_fields(tokens: dict[str, str | None]) -> dict[str, str | None]:
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
            except Exception as e:
                print(f"Warning: Failed to encrypt {field}: {e}")
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
            except Exception as e:
                print(f"Warning: Failed to decrypt {field}: {e}")
                # Keep original value if decryption fails (might be unencrypted)
                decrypted_tokens[field] = tokens[field]

    return decrypted_tokens


def save_tokens(tokens: dict[str, str | None]) -> None:
    print("Saving tokens (sensitive fields will be encrypted)")
    # Encrypt sensitive fields before storing
    encrypted_tokens = encrypt_sensitive_fields(tokens)
    redis.hset(USER_KEY, mapping={"tokens": json.dumps(encrypted_tokens)})

    # Set TTL based on token expiry
    expiry_str = tokens.get("expiry")
    if expiry_str:
        try:
            expiry_dt = datetime.fromisoformat(str(expiry_str).replace("Z", "+00:00"))
            # If the datetime is naive (no timezone), assume it's UTC
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=UTC)
            now = datetime.now(UTC)
            ttl_seconds = int((expiry_dt - now).total_seconds())
            print(f"TTL seconds: {ttl_seconds}")

            # Set TTL, but ensure it's at least 1 minute and at most 7 days
            ttl_seconds = max(60, min(ttl_seconds, 7 * 24 * 3600))
            redis.expire(USER_KEY, ttl_seconds)
            print(f"Set token TTL to {ttl_seconds} seconds (expires: {expiry_dt})")
        except (ValueError, TypeError) as e:
            print(f"Warning: Could not parse token expiry, setting default TTL: {e}")
            # Default to 1 hour if expiry parsing fails
            redis.expire(USER_KEY, 3600)
    else:
        # Default to 1 hour if no expiry provided
        redis.expire(USER_KEY, 3600)


def load_tokens() -> dict[str, str | None] | None:
    raw = redis.hget(USER_KEY, "tokens")
    if not raw:
        return None

    encrypted_tokens = json.loads(str(raw))

    # Decrypt sensitive fields
    tokens = decrypt_sensitive_fields(encrypted_tokens)

    # Check if token is expired
    if is_token_expired(tokens):
        print("Token has expired, removing from Redis")
        redis.delete(USER_KEY)
        return None

    return tokens


def is_token_expired(tokens: dict[str, str | None]) -> bool:
    """Check if the token has expired based on the expiry field."""
    expiry_str = tokens.get("expiry")
    print(f"Expiry string: {expiry_str}")
    if not expiry_str:
        return False  # No expiry info, assume valid

    try:
        expiry_dt = datetime.fromisoformat(str(expiry_str).replace("Z", "+00:00"))
        # If the datetime is naive (no timezone), assume it's UTC
        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        return now >= expiry_dt
    except (ValueError, TypeError):
        # If we can't parse expiry, assume it's valid
        return False


def save_timezone(tz: str) -> None:
    redis.hset(USER_KEY, "tz", tz)


def load_timezone() -> str:
    tz = redis.hget(USER_KEY, "tz")
    return str(tz) if tz else settings.default_tz


def set_idempotency(key: str, ttl_sec: int = 600) -> None:
    redis.setex(f"idem:{key}", ttl_sec, "1")


def has_idempotency(key: str) -> bool:
    return redis.exists(f"idem:{key}") == 1
