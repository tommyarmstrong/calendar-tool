from __future__ import annotations

import base64
import tempfile
import uuid
from typing import Any

import requests
from app.config import (
    CALENDAR_BEARER_TOKEN,
    CALENDAR_MCP_CA_CERT_B64,
    CALENDAR_MCP_CLIENT_P12,  # base64 of .p12 (cert+key)
    CALENDAR_MCP_CLIENT_P12_PASSWORD,  # password or ""
    CALENDAR_MCP_URL,
)
from requests_pkcs12 import Pkcs12Adapter

_TIMEOUT = 30.0


def _mk_verify_setting() -> bool | str:
    """
    Decide what to pass to requests for server verification:
      - path to a CA bundle file (str), or
      - True (system CAs), or
      - False (NOT recommended; dev-only).
    If CALENDAR_MCP_CA_CERT_B64 is provided, then materialize a temp file.
    """

    if CALENDAR_MCP_CA_CERT_B64:
        pem_bytes = base64.b64decode(CALENDAR_MCP_CA_CERT_B64)
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        tf.write(pem_bytes)
        tf.flush()
        tf.close()
        return tf.name

    # Default: use system trust (works with ACM/public certs)
    return True


def _build_session() -> requests.Session:
    if not CALENDAR_MCP_CLIENT_P12:
        raise RuntimeError(
            "CALENDAR_MCP_CLIENT_P12 is empty; provide base64 of the client .p12 (cert+key)."
        )

    try:
        p12_bytes = base64.b64decode(CALENDAR_MCP_CLIENT_P12)
    except Exception as e:
        raise RuntimeError("CALENDAR_MCP_CLIENT_P12 is not valid base64") from e

    session = requests.Session()
    session.mount(
        "https://",
        Pkcs12Adapter(
            pkcs12_data=p12_bytes,
            pkcs12_password=(CALENDAR_MCP_CLIENT_P12_PASSWORD or ""),
        ),
    )
    # Keep legacy bearer & headers
    session.headers.update({
        "Authorization": f"Bearer {CALENDAR_BEARER_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return session


_session = _build_session()


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
        resp = _session.post(
            url, json=payload, headers=headers, timeout=_TIMEOUT, verify=_mk_verify_setting()
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
