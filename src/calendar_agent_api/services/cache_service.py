import json
from typing import Any

import redis


class RedisCache:
    def __init__(
        self,
        redis_host: str,
        redis_port: int,
        redis_password: str,
    ):
        self.client = redis.Redis(
            host=redis_host, port=redis_port, password=redis_password, decode_responses=True
        )

    @staticmethod
    def get_status_key(request_id: str) -> str:
        return f"mcp:cache:status:{request_id}"

    def set_json(self, key: str, value: dict[str, Any], ttl: int | None = None) -> None:
        data = json.dumps(value)
        if ttl:
            self.client.setex(key, ttl, data)
        else:
            self.client.set(key, data)

    def get_json(self, key: str) -> dict[str, Any] | None:
        raw = self.client.get(key)
        if raw is not None:
            # Type assertion: Redis client with decode_responses=True returns str
            result = json.loads(str(raw))
            return result if isinstance(result, dict) else None
        return None

    def set_status(self, key: str, status: str, ttl: int | None = None) -> None:
        self.set_json(key, {"status": status}, ttl)

    def get_status(self, key: str) -> str | None:
        result = self.get_json(key)
        return result.get("status") if result else None
