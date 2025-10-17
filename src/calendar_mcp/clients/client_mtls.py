#!/usr/bin/env python3
import json
import os
from typing import Any

import requests

# Base URL (use your custom domain so mTLS is enforced)
BASE = os.getenv("CALENDAR_MCP_URL", "https://calendar-mcp.tommyarmstrong.uk")

# Bearer token stays exactly as you had it
TOKEN = os.getenv("CALENDAR_BEARER_TOKEN", "dev-test-token")

# NEW: paths to your client certificate and private key (PEM files)
# Provide these via env vars; if not set, we'll try sensible defaults.
CLIENT_CERT_PATH = os.getenv("CALENDAR_MCP_CLIENT_CERT_PATH", "certificates/client.crt")
CLIENT_KEY_PATH = os.getenv("CALENDAR_MCP_CLIENT_KEY_PATH", "certificates/client.key")
CA_BUNDLE = os.getenv("CALENDAR_MCP_CA_BUNDLE", "certificates/ca.crt")


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    # mTLS: pass client cert & key; 'verify=True' uses system CAs for the server (ACM public certs)
    r = requests.post(
        f"{BASE}/mcp/tools/call",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={"name": name, "arguments": arguments},
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),  # <- mTLS required by the API Gateway
        verify=CA_BUNDLE,  # <-- trust the CA here
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
