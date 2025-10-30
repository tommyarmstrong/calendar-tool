from __future__ import annotations

import base64

import requests
from app.config import get_settings
from requests_pkcs12 import Pkcs12Adapter


def session_with_pkcs12() -> requests.Session:
    """
    Create a requests session configured for mTLS authentication using PKCS#12 certificates.

    This function sets up a requests session with mutual TLS (mTLS) authentication
    for secure communication with the calendar MCP service. It configures the session
    with client certificates and appropriate headers for API communication.

    The session is configured with:
    - PKCS#12 client certificate for mTLS authentication (HTTPS only)
    - Bearer token authorization header
    - Standard JSON content-type headers

    Returns:
        requests.Session: A configured requests session ready for API calls

    Raises:
        RuntimeError: If CALENDAR_MCP_CLIENT_P12 is empty or invalid base64
        Exception: If PKCS#12 certificate decoding fails
    """
    settings = get_settings()
    calendar_mcp_url = settings.calendar_mcp_url
    calendar_mcp_client_p12 = settings.calendar_mcp_client_p12
    calendar_mcp_client_p12_password = settings.calendar_mcp_client_p12_password

    session = requests.Session()

    # Only set up mTLS for HTTPS connections
    if calendar_mcp_url and calendar_mcp_url.startswith("https://"):
        if not calendar_mcp_client_p12:
            raise RuntimeError(
                "CALENDAR_MCP_CLIENT_P12 is empty; provide base64 of the client .p12 (cert+key)."
            )

        try:
            p12_bytes = base64.b64decode(calendar_mcp_client_p12)
        except Exception as e:
            raise RuntimeError("CALENDAR_MCP_CLIENT_P12 is not valid base64") from e

        adapter = Pkcs12Adapter(
            pkcs12_data=p12_bytes,
            pkcs12_password=(calendar_mcp_client_p12_password or ""),
        )
        session.mount(
            calendar_mcp_url,  # <-- Use base URL so the mTLS certs are not sent to other domains
            adapter,
        )

    # Keep standard headers
    session.headers.update({
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return session
