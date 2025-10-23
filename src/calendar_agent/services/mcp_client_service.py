from __future__ import annotations

import uuid
from typing import Any

from app.config import CALENDAR_MCP_URL
from services.response_helpers import requests_verify_setting, session_with_pkcs12

_TIMEOUT = 30.0


def call_mcp(name: str, arguments: dict[str, Any] | None) -> Any:
    """
    Call the MCP tool endpoint over mTLS (client PKCS#12) and verify server with provided CA.
    """
    if not name:
        raise ValueError("Tool 'name' is required")

    payload: dict[str, Any] = {"name": name, "arguments": arguments or {}}
    url = f"{CALENDAR_MCP_URL}/mcp/tools/call"

    req_id = str(uuid.uuid4())
    headers = {"X-Request-ID": req_id}

    try:
        session = session_with_pkcs12()
        resp = session.post(
            url, json=payload, headers=headers, timeout=_TIMEOUT, verify=requests_verify_setting()
        )
        resp.raise_for_status()
    except Exception as e:
        raise Exception(f"MCP request failed ({url}): {e}") from e

    ctype = resp.headers.get("content-type", "")
    if "application/json" not in ctype:
        try:
            return resp.json()
        except Exception as ee:
            raise RuntimeError(f"MCP returned non-JSON content-type ({ctype})") from ee

    return resp.json()
