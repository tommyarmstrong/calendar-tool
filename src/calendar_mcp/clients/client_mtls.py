#!/usr/bin/env python3
import base64
import json
import os
import tempfile
from typing import Any

import requests
from requests_pkcs12 import Pkcs12Adapter

# Base URL (use your custom domain so mTLS is enforced)
BASE = os.getenv("CALENDAR_MCP_URL", "https://calendar-mcp.tommyarmstrong.uk")

# Bearer token stays exactly as you had it
TOKEN = os.getenv("CALENDAR_BEARER_TOKEN", "dev-test-token")

# P12 bundle and password (consistent with Calendar Agent)
CLIENT_P12_B64 = os.getenv("CALENDAR_MCP_CLIENT_P12")
CLIENT_P12_PASSWORD = os.getenv("CALENDAR_MCP_CLIENT_P12_PASSWORD")

# CA certificate as base64 (consistent with Calendar Agent)
CA_CERT_B64 = os.getenv("CALENDAR_MCP_CA_CERT_B64")


def _get_verify_setting() -> bool | str:
    """
    Get the verify setting for requests.
    If CALENDAR_MCP_CA_CERT_B64 is provided, create a temp file from base64.
    Otherwise, use system CAs or fallback to file path.
    """
    if CA_CERT_B64:
        try:
            ca_bytes = base64.b64decode(CA_CERT_B64)
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
            tf.write(ca_bytes)
            tf.flush()
            tf.close()
            return tf.name
        except Exception as e:
            print(f"Warning: Failed to decode CA certificate: {e}")
            return True  # Fallback to system CAs

    # Fallback to file path if base64 not provided
    fallback_path = "certificates/ca.crt"
    if os.path.exists(fallback_path):
        return fallback_path

    return True  # Use system CAs


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    # mTLS: use P12 bundle for client authentication (consistent with Calendar Agent)
    if not CLIENT_P12_B64:
        raise RuntimeError("CALENDAR_MCP_CLIENT_P12 is required for mTLS authentication")

    if not CLIENT_P12_PASSWORD:
        raise RuntimeError("CALENDAR_MCP_CLIENT_P12_PASSWORD is required for mTLS authentication")

    try:
        p12_bytes = base64.b64decode(CLIENT_P12_B64)
    except Exception as e:
        raise RuntimeError("CALENDAR_MCP_CLIENT_P12 is not valid base64") from e

    # Create session with Pkcs12Adapter (same as Calendar Agent)
    session = requests.Session()
    session.mount(
        "https://",
        Pkcs12Adapter(
            pkcs12_data=p12_bytes,
            pkcs12_password=CLIENT_P12_PASSWORD,
        ),
    )

    r = session.post(
        f"{BASE}/mcp/tools/call",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={"name": name, "arguments": arguments},
        verify=_get_verify_setting(),  # <-- trust the CA here (base64 or file)
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    print(
        json.dumps(
            call_tool(
                "calendar.freebusy",
                {
                    "window_start": "2025-10-08T08:00:00+01:00",
                    "window_end": "2025-10-08T18:00:00+01:00",
                    "calendars": ["primary"],
                },
            ),
            indent=2,
        )
    )
