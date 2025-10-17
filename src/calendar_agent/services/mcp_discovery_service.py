# src/agent/mcp_discovery.py
import base64
import tempfile
from typing import Any

import requests
from app.config import (
    CALENDAR_BEARER_TOKEN,
    CALENDAR_MCP_CA_CERT_B64,
    CALENDAR_MCP_CLIENT_P12,
    CALENDAR_MCP_CLIENT_P12_PASSWORD,
    CALENDAR_MCP_URL,
    REDIS_CACHE_PATH,
    REDIS_CACHE_TTL,
    REDIS_HOST,
    REDIS_PASSWORD,
    REDIS_PORT,
)
from requests_pkcs12 import Pkcs12Adapter
from services.cache_service import RedisCache

_session: requests.Session | None = None
_ca_tmp_path: str | None = None


def _session_with_pkcs12() -> requests.Session:
    global _session, _ca_tmp_path
    if _session is not None:
        return _session

    assert CALENDAR_MCP_CLIENT_P12 is not None
    assert CALENDAR_MCP_CLIENT_P12_PASSWORD is not None
    p12_bytes = base64.b64decode(CALENDAR_MCP_CLIENT_P12)

    session = requests.Session()
    session.mount(
        "https://",
        Pkcs12Adapter(
            pkcs12_data=p12_bytes,
            pkcs12_password=CALENDAR_MCP_CLIENT_P12_PASSWORD or "",
        ),
    )

    # Trust the server using the CA cert provided as base64 (self-signed/dev PKI).
    # If CALENDAR_MCP_CA_CERT_B64 is empty/None, requests will use system CAs.
    if CALENDAR_MCP_CA_CERT_B64:
        try:
            ca_bytes = base64.b64decode(CALENDAR_MCP_CA_CERT_B64)
        except Exception as e:
            raise RuntimeError("CALENDAR_MCP_CA_CERT_B64 is not valid base64") from e
        tf = tempfile.NamedTemporaryFile(prefix="mcp-ca-", suffix=".pem", delete=False)
        tf.write(ca_bytes)
        tf.flush()
        tf.close()
        _ca_tmp_path = tf.name

    _session = session
    return session


def _get(path: str) -> Any:
    session = _session_with_pkcs12()
    headers = (
        {"Authorization": f"Bearer {CALENDAR_BEARER_TOKEN}"} if path.startswith("/mcp/") else {}
    )
    verify = _ca_tmp_path if _ca_tmp_path else True
    r = session.get(f"{CALENDAR_MCP_URL}{path}", headers=headers, timeout=15, verify=verify)
    r.raise_for_status()
    return r.json()


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
