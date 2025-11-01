# src/agent/mcp_discovery.py
import uuid
from typing import Any

from app.config import REDIS_CACHE_PATH, REDIS_CACHE_TTL, get_settings
from infrastructure.platform_manager import requests_verify_setting
from services.cache_service import RedisCache
from services.hmac_service import hmac_headers_for_get
from services.response_helpers import session_with_pkcs12

_TIMEOUT = 15


def _get(path: str) -> Any:
    session = session_with_pkcs12()
    settings = get_settings()

    req_id = str(uuid.uuid4())
    base_headers = {"X-Request-ID": req_id, "Accept": "application/json"}
    url = f"{settings.calendar_mcp_url}{path}"

    # Add HMAC headers (does not overwrite existing keys)
    hmac_headers = hmac_headers_for_get(path)
    headers = {**base_headers, **hmac_headers}
    print(f"headers: {headers}")

    try:
        resp = session.get(url, headers=headers, timeout=_TIMEOUT, verify=requests_verify_setting())
        resp.raise_for_status()

    except Exception as e:
        raise Exception(f"MCP request failed ({settings.calendar_mcp_url}{path}): {e}") from e

    return resp.json()


def get_tools_and_schemas() -> dict[str, Any]:
    settings = get_settings()
    manifest = None
    tools = None
    schemas = None

    if not all([settings.redis_host, settings.redis_port, settings.redis_password]):
        raise ValueError("Redis configuration is incomplete")
    assert (
        settings.redis_host is not None
        and settings.redis_port is not None
        and settings.redis_password is not None
    )
    cache = RedisCache(settings.redis_host, int(settings.redis_port), settings.redis_password)
    retrieved = cache.get_json(REDIS_CACHE_PATH)

    if retrieved:
        manifest = retrieved.get("manifest")
        tools = retrieved.get("tools")
        schemas = retrieved.get("schemas")

    fetched_from_mcp = False
    if not manifest:
        manifest = _get("/.well-known/mcp/manifest")
        fetched_from_mcp = True
    if not tools:
        mcp_tools = _get("/mcp/tools")
        tools = mcp_tools.get("tools", [])
        fetched_from_mcp = True
    if not schemas:
        schemas = _get("/mcp/schemas")
        fetched_from_mcp = True

    val = {"manifest": manifest, "tools": tools, "schemas": schemas}

    if fetched_from_mcp:
        cache.set_json(REDIS_CACHE_PATH, val, ttl=REDIS_CACHE_TTL)

    return val
