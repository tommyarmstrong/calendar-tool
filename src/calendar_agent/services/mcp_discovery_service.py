# src/agent/mcp_discovery.py
import uuid
from typing import Any

from app.config import (
    CALENDAR_MCP_URL,
    REDIS_CACHE_PATH,
    REDIS_CACHE_TTL,
    REDIS_HOST,
    REDIS_PASSWORD,
    REDIS_PORT,
)
from infrastructure.platform_manager import create_logger
from services.cache_service import RedisCache
from services.response_helpers import requests_verify_setting, session_with_pkcs12

_TIMEOUT = 15

logger = create_logger(logger_name="calendar-agent", log_level="INFO")


def _get(path: str) -> Any:
    session = session_with_pkcs12()

    req_id = str(uuid.uuid4())
    headers = {"X-Request-ID": req_id}
    url = f"{CALENDAR_MCP_URL}{path}"

    try:
        logger.info(f"Sending GET request to {url}")
        resp = session.get(url, headers=headers, timeout=_TIMEOUT, verify=requests_verify_setting())
        resp.raise_for_status()

    except Exception as e:
        raise Exception(f"MCP request failed ({CALENDAR_MCP_URL}{path}): {e}") from e

    return resp.json()


def get_tools_and_schemas() -> dict[str, Any]:
    manifest = None
    tools = None
    schemas = None

    if not all([REDIS_HOST, REDIS_PORT, REDIS_PASSWORD]):
        raise ValueError("Redis configuration is incomplete")
    assert REDIS_HOST is not None and REDIS_PORT is not None and REDIS_PASSWORD is not None
    cache = RedisCache(REDIS_HOST, int(REDIS_PORT), REDIS_PASSWORD)
    retrieved = cache.get_json(REDIS_CACHE_PATH)

    if retrieved:
        manifest = retrieved.get("manifest")
        tools = retrieved.get("tools")
        schemas = retrieved.get("schemas")
        logger.info("Retrieved MCP manifest, tools, and schemas from cache")

    fetched_from_mcp = False
    if not manifest:
        manifest = _get("/.well-known/mcp/manifest")
        logger.info("Fetched MCP manifest from MCP")
        fetched_from_mcp = True
    if not tools:
        mcp_tools = _get("/mcp/tools")
        tools = mcp_tools.get("tools", [])
        logger.info("Fetched MCP tools from MCP")
        fetched_from_mcp = True
    if not schemas:
        schemas = _get("/mcp/schemas")
        logger.info("Fetched MCP schemas from MCP")
        fetched_from_mcp = True

    val = {"manifest": manifest, "tools": tools, "schemas": schemas}

    if fetched_from_mcp:
        logger.info("Writing MCP manifest, tools, and schemas to cache")
        cache.set_json(REDIS_CACHE_PATH, val, ttl=REDIS_CACHE_TTL)

    return val
