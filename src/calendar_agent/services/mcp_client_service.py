from __future__ import annotations

import uuid
from typing import Any

from app.config import get_settings
from services.hmac_service import hmac_headers_for_request, json_bytes_for_hmac
from services.requests_helpers import requests_verify_setting, session_with_pkcs12

_TIMEOUT = 30.0


def call_mcp(name: str, arguments: dict[str, Any] | None) -> Any:
    """
    Call the MCP tool endpoint over mTLS (client PKCS#12) and verify server with provided CA.
    """
    if not name:
        raise ValueError("Tool 'name' is required")

    settings = get_settings()
    payload: dict[str, Any] = {"name": name, "arguments": arguments or {}}
    body_bytes = json_bytes_for_hmac(payload)

    path = "/mcp/tools/call"
    url = f"{settings.calendar_mcp_url}{path}"

    # Add standard headers
    req_id = str(uuid.uuid4())
    headers = {
        "X-Request-ID": req_id,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    # Add HMAC headers
    hmac_headers = hmac_headers_for_request(path, "POST", body_bytes)
    headers = {**headers, **hmac_headers}

    # Get verify settings
    verify = requests_verify_setting()

    try:
        session = session_with_pkcs12()
        resp = session.post(
            url,
            data=body_bytes,
            headers=headers,
            timeout=_TIMEOUT,
            verify=verify,
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
