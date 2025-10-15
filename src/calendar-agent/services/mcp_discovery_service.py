# src/agent/mcp_discovery.py
from typing import Any

import requests

from app.config import (
    CALENDAR_BEARER_TOKEN,
    CALENDAR_MCP_URL,
    REDIS_CACHE_PATH,
    REDIS_CACHE_TTL,
    REDIS_HOST,
    REDIS_PASSWORD,
    REDIS_PORT,
)
from services.cache_service import RedisCache


def _get(path: str) -> Any:
    r = requests.get(
        f"{CALENDAR_MCP_URL}{path}",
        headers={"Authorization": f"Bearer {CALENDAR_BEARER_TOKEN}"}
        if path.startswith("/mcp/")
        else {},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def get_tools_and_schemas() -> dict[str, Any]:
    manifest = None  # no auth by design
    tools = None  # { "tools": [...] }
    schemas = None  # { name: {input_schema...}, ... }

    # Read from redis cache if available
    if not all([REDIS_HOST, REDIS_PORT, REDIS_PASSWORD]):
        raise ValueError("Redis configuration is incomplete")
    assert REDIS_HOST is not None and REDIS_PORT is not None and REDIS_PASSWORD is not None
    cache = RedisCache(REDIS_HOST, int(REDIS_PORT), REDIS_PASSWORD)
    retrieved = cache.get_json(REDIS_CACHE_PATH)

    if retrieved:
        manifest = retrieved.get("manifest")
        tools = retrieved.get("tools")
        schemas = retrieved.get("schemas")

    # Read from MCP if not available in cache
    fetched_from_mcp = False
    if not manifest:
        manifest = _get("/.well-known/mcp/manifest")
        fetched_from_mcp = True
    if not tools:
        mcp_tools = _get("/mcp/tools")
        tools = mcp_tools.get("tools", [])  # Extract the list
        fetched_from_mcp = True
    if not schemas:
        schemas = _get("/mcp/schemas")
        fetched_from_mcp = True

    val = {"manifest": manifest, "tools": tools, "schemas": schemas}

    # Cache the value only if any data was fetched from MCP
    if fetched_from_mcp:
        cache.set_json(REDIS_CACHE_PATH, val, ttl=REDIS_CACHE_TTL)

    return val
