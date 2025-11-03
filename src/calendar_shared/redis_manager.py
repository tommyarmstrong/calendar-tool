from __future__ import annotations

import json
from typing import Any, Protocol, cast

from redis import Redis


class _FernetLike(Protocol):
    def encrypt(self, data: bytes) -> bytes: ...
    def decrypt(self, token: bytes) -> bytes: ...


class RedisManager:
    """
    High-level Redis utilities for JSON cache, status tracking, idempotency/nonce control,
    and Fernet-encrypted token storage.

    This class is designed for dependency injection: callers provide a configured
    Redis client (e.g., via Redis.from_url or Redis(host=..., ...)) and optional
    configuration such as key namespaces and encryption keys.

    Args:
        redis_client (Redis): A configured Redis client instance.
        namespace (str): Key namespace/prefix for generated keys.
        token_encryption_key (bytes | None): Fernet key used to encrypt/decrypt
            sensitive token fields. If None, token operations requiring encryption
            will raise a ValueError.
        default_nonce_ttl (int): TTL in seconds for nonce uniqueness tracking.
        default_idem_ttl (int): Default TTL for idempotency keys.
        default_token_ttl (int): Default TTL for stored tokens.

    Note:
        - This module intentionally avoids importing service-specific settings.
          Construct the manager in your service layer using your local config and
          pass it into call sites.
    """

    def __init__(
        self,
        redis_client: Redis,
        *,
        namespace: str = "calendar:mcp",
        token_encryption_key: bytes | None = None,
        fernet: _FernetLike | None = None,
        default_nonce_ttl: int = 300,
        default_idem_ttl: int = 600,
        default_token_ttl: int = 3600,
    ) -> None:
        self._redis: Redis = redis_client
        self._namespace: str = namespace.rstrip(":")
        self._token_encryption_key: bytes | None = token_encryption_key
        self._fernet: _FernetLike | None = fernet
        self._default_nonce_ttl: int = default_nonce_ttl
        self._default_idem_ttl: int = default_idem_ttl
        self._default_token_ttl: int = default_token_ttl

    # -----------------------------
    # JSON cache helpers
    # -----------------------------
    def set_json(self, key: str, value: dict[str, Any], ttl: int | None = None) -> None:
        """
        Set a JSON value at `key` with optional TTL.

        Args:
            key (str): The Redis key to set.
            value (dict[str, Any]): The JSON-serializable mapping to store.
            ttl (int | None): Optional TTL in seconds; if None, no expiry is set.
        """
        data = json.dumps(value)
        if ttl is not None:
            self._redis.setex(key, ttl, data)
        else:
            self._redis.set(key, data)

    def get_json(self, key: str) -> dict[str, Any] | None:
        """
        Get a JSON value from `key` and parse it into a dict.

        Args:
            key (str): The Redis key to get.

        Returns:
            dict[str, Any] | None: Parsed dict if present and valid; otherwise None.
        """
        raw = self._redis.get(key)
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    # -----------------------------
    # Status helpers
    # -----------------------------
    def get_status_key(self, request_id: str) -> str:
        """
        Build a namespaced status key for a given request id.

        Args:
            request_id (str): Request identifier.

        Returns:
            str: A namespaced Redis key for status tracking.
        """
        return f"{self._namespace}:cache:status:{request_id}"

    def set_status(self, key: str, status: str, ttl: int | None = None) -> None:
        """
        Set a simple status string under `key` as a JSON object.

        Args:
            key (str): The Redis key to set.
            status (str): Status message/value.
            ttl (int | None): Optional TTL in seconds.
        """
        self.set_json(key, {"status": status}, ttl)

    def get_status(self, key: str) -> str | None:
        """
        Get a simple status string from `key` if present.

        Args:
            key (str): The Redis key to look up.

        Returns:
            str | None: The status value or None if not present.
        """
        result = self.get_json(key)
        return result.get("status") if result else None

    def set_status_update(
        self, request_id: str, status_code: str, message: str, *, ttl: int = 900
    ) -> None:
        """
        Store a status update payload for a request id.

        Args:
            request_id (str): Request identifier.
            status_code (str): Domain or HTTP-like status code string.
            message (str): Human-readable status message.
            ttl (int): Time-to-live in seconds (default 900 seconds).
        """
        key = self.get_status_key(request_id)
        self.set_json(key, {"status_code": status_code, "message": message}, ttl=ttl)

    # -----------------------------
    # Nonce and idempotency helpers
    # -----------------------------
    def is_nonce_unique(self, nonce: str, *, ttl: int | None = None) -> bool:
        """
        Check and record nonce uniqueness for a limited time window.

        Args:
            nonce (str): The nonce value.
            ttl (int | None): TTL in seconds; defaults to manager's nonce TTL.

        Returns:
            bool: True if nonce not seen in window and now recorded; False otherwise.
        """
        ttl_to_use = ttl if ttl is not None else self._default_nonce_ttl
        key = f"{self._namespace}:x-agent-nonce:{nonce}"
        if self._redis.exists(key):
            return False
        self._redis.setex(key, ttl_to_use, "used")
        return True

    def set_idempotency(self, key: str, *, ttl: int | None = None) -> None:
        """
        Set an idempotency key with TTL.

        Args:
            key (str): Idempotency key identifier.
            ttl (int | None): TTL in seconds; defaults to manager's idempotency TTL.
        """
        ttl_to_use = ttl if ttl is not None else self._default_idem_ttl
        self._redis.setex(f"{self._namespace}:idem:{key}", ttl_to_use, "1")

    def has_idempotency(self, key: str) -> bool:
        """
        Check if an idempotency key exists.

        Args:
            key (str): Idempotency key identifier.

        Returns:
            bool: True if the key exists; otherwise False.
        """
        return self._redis.exists(f"{self._namespace}:idem:{key}") == 1

    # -----------------------------
    # Token encryption helpers
    # -----------------------------

    def encrypt_sensitive_fields(
        self, tokens: dict[str, str | list[str] | None]
    ) -> dict[str, str | list[str] | None]:
        """
        Encrypt sensitive token fields; leave non-sensitive fields unchanged.

        Args:
            tokens (dict[str, str | list[str] | None]): Token mapping to process.

        Returns:
            dict[str, str | list[str] | None]: New mapping with encrypted sensitive fields.
        """
        if not tokens:
            return tokens

        encrypted_tokens = tokens.copy()
        for field in ["token", "refresh_token", "client_secret"]:
            if field in tokens and tokens[field]:
                try:
                    fernet = cast(_FernetLike, self._fernet)
                    ciphertext = fernet.encrypt(str(tokens[field]).encode())
                    encrypted_tokens[field] = ciphertext.decode()
                except Exception:
                    encrypted_tokens[field] = tokens[field]
        return encrypted_tokens

    def decrypt_sensitive_fields(self, tokens: dict[str, str | None]) -> dict[str, str | None]:
        """
        Decrypt sensitive token fields; leave non-sensitive fields unchanged.

        Args:
            tokens (dict[str, str | None]): Token mapping to process.

        Returns:
            dict[str, str | None]: New mapping with decrypted sensitive fields when possible.
        """
        if not tokens:
            return tokens

        decrypted_tokens = tokens.copy()
        for field in ["token", "refresh_token", "client_secret"]:
            if field in tokens and tokens[field]:
                try:
                    fernet = cast(_FernetLike, self._fernet)
                    plaintext = fernet.decrypt(str(tokens[field]).encode())
                    decrypted_tokens[field] = plaintext.decode()
                except Exception:
                    decrypted_tokens[field] = tokens[field]
        return decrypted_tokens

    # -----------------------------
    # Token storage
    # -----------------------------
    def save_tokens(
        self,
        user_key: str,
        tokens: dict[str, str | list[str] | None],
        *,
        ttl: int | None = None,
    ) -> None:
        """
        Save token dict for `user_key` with encryption and expiry.

        Args:
            user_key (str): Logical user identifier (will be namespaced).
            tokens (dict[str, str | list[str] | None]): Token mapping to store.
            ttl (int | None): TTL for the token record; defaults to manager's token TTL.
        """
        encrypted = self.encrypt_sensitive_fields(tokens)
        key = f"{self._namespace}:oauth:{user_key}"
        self._redis.hset(key, mapping={"tokens": json.dumps(encrypted)})
        ttl_to_use = ttl if ttl is not None else self._default_token_ttl
        self._redis.expire(key, ttl_to_use)

    def load_tokens(self, user_key: str) -> dict[str, str | None] | None:
        """
        Load token dict for `user_key` and decrypt sensitive fields.

        Args:
            user_key (str): Logical user identifier (namespaced internally).

        Returns:
            dict[str, str | None] | None: Decrypted token mapping or None if missing.
        """
        key = f"{self._namespace}:oauth:{user_key}"
        raw = self._redis.hget(key, "tokens")
        if not raw:
            return None
        try:
            encrypted = json.loads(str(raw))
        except Exception:
            return None
        return self.decrypt_sensitive_fields(encrypted)

    def purge_tokens(self, user_key: str) -> None:
        """
        Delete all token data for `user_key`.

        Args:
            user_key (str): Logical user identifier (namespaced internally).
        """
        key = f"{self._namespace}:oauth:{user_key}"
        self._redis.delete(key)


def build_redis_manager(
    redis_url: str | None = None,
    *,
    redis_client: Redis | None = None,
    namespace: str = "mcp:calendar",
    token_encryption_key: bytes | None = None,
    fernet: Any | None = None,
    default_nonce_ttl: int = 300,
    default_idem_ttl: int = 600,
    default_token_ttl: int = 3600,
    decode_responses: bool = True,
) -> RedisManager:
    """
    Factory to create a RedisManager with sensible defaults.

    You can provide either `redis_url` (preferred) and this function will initialize
    the client, or pass an existing `redis_client` (for tests/advanced use).

    Args:
        redis_url (str | None): Redis connection URL (e.g., "redis://:pwd@host:6379/0").
        redis_client (Redis | None): Pre-configured Redis client instance.
        namespace (str): Key namespace/prefix for generated keys.
        token_encryption_key (bytes | None): Fernet key for token encryption.
        default_nonce_ttl (int): Default TTL for nonce uniqueness tracking.
        default_idem_ttl (int): Default TTL for idempotency keys.
        default_token_ttl (int): Default TTL for stored tokens.
        decode_responses (bool): If creating the client, whether to decode responses.

    Returns:
        RedisManager: Configured manager instance.
    """
    if redis_client is None:
        if not redis_url:
            raise ValueError("Provide either redis_url or redis_client")
        # Use literal True/False to satisfy type checker's overload selection
        if decode_responses:
            redis_client = Redis.from_url(redis_url, decode_responses=True)
        else:
            redis_client = Redis.from_url(redis_url, decode_responses=False)

    return RedisManager(
        redis_client,
        namespace=namespace,
        token_encryption_key=token_encryption_key,
        fernet=fernet,
        default_nonce_ttl=default_nonce_ttl,
        default_idem_ttl=default_idem_ttl,
        default_token_ttl=default_token_ttl,
    )
