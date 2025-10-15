from __future__ import annotations

# src/agent/mcp_client.py
import uuid
from typing import Any

import requests

from app.config import CALENDAR_BEARER_TOKEN, CALENDAR_MCP_URL

_TIMEOUT = 30.0

_session = requests.Session()
_session.headers.update({
    "Authorization": f"Bearer {CALENDAR_BEARER_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
})


def call_mcp(name: str, arguments: dict[str, Any] | None) -> Any:
    """
    Call the MCP tool endpoint.

    Args:
        name: MCP tool name (e.g., 'calendar.freebusy' or 'calendar.create_event')
        arguments: dict of tool arguments (use {} if None)

    Returns:
        Parsed JSON from MCP (usually a dict).

    Raises:
        RuntimeError: on HTTP/network errors or non-JSON responses.
    """
    if not name:
        raise ValueError("Tool 'name' is required")

    payload: dict[str, Any] = {"name": name, "arguments": arguments or {}}
    url = f"{CALENDAR_MCP_URL}/mcp/tools/call"

    # Optional id for tracing across logs
    req_id = str(uuid.uuid4())
    headers = {"X-Request-ID": req_id}

    try:
        resp = _session.post(url, json=payload, headers=headers, timeout=_TIMEOUT)
        # Raise for 4xx/5xx to hit the except block below
        resp.raise_for_status()
    except Exception as e:
        raise Exception(f"MCP request failed ({url}): {e}") from e

    # Ensure JSON
    ctype = resp.headers.get("content-type", "")
    if "application/json" not in ctype:
        # still try to parse; else raise
        try:
            return resp.json()
        except Exception as e:
            raise RuntimeError(f"MCP returned non-JSON content-type ({ctype})") from e

    return resp.json()
