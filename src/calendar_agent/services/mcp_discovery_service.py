# src/agent/mcp_discovery.py
import uuid
from typing import Any

from app.config import MCP_SCHEMA_CACHE, MCP_SCHEMA_TTL, get_settings
from infrastructure.redis_manager import build_redis_manager
from services.hmac_service import hmac_headers_for_request
from services.requests_helpers import requests_verify_setting, session_with_pkcs12

_TIMEOUT = 15


def _get(path: str) -> Any:
    session = session_with_pkcs12()
    settings = get_settings()

    req_id = str(uuid.uuid4())
    base_headers = {"X-Request-ID": req_id, "Accept": "application/json"}
    url = f"{settings.calendar_mcp_url}{path}"

    # Add HMAC headers (does not overwrite existing keys)
    hmac_headers = hmac_headers_for_request(path, "GET")
    headers = {**base_headers, **hmac_headers}

    try:
        resp = session.get(url, headers=headers, timeout=_TIMEOUT, verify=requests_verify_setting())
        resp.raise_for_status()

    except Exception as e:
        raise Exception(f"MCP request failed ({settings.calendar_mcp_url}{path}): {e}") from e

    return resp.json()


def get_tools_and_schemas() -> dict[str, Any]:
    settings = get_settings()
    redis_manager = build_redis_manager(settings.redis_url)
    manifest = None
    tools = None
    schemas = None

    retrieved = redis_manager.get_json(MCP_SCHEMA_CACHE)

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
        redis_manager.set_json(MCP_SCHEMA_CACHE, val, ttl=MCP_SCHEMA_TTL)

    return val
