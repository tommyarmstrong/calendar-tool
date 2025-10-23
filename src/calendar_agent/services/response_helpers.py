from __future__ import annotations

import base64
import tempfile

import requests
from app.config import (
    CALENDAR_BEARER_TOKEN,
    CALENDAR_MCP_CA_CERT_B64,
    CALENDAR_MCP_CLIENT_P12,
    CALENDAR_MCP_CLIENT_P12_PASSWORD,
    CALENDAR_MCP_URL,
)
from requests_pkcs12 import Pkcs12Adapter


def requests_verify_setting() -> bool | str:
    """
    Determine the TLS certificate verification setting for requests.

    Returns the appropriate verification setting for TLS connections:
    - A temporary file path to a CA certificate for localhost development with self-signed certs
    - True for system-trusted certificates (production environments)

    For localhost HTTPS connections with self-signed certificates, this function
    creates a temporary file containing the base64-decoded CA certificate and
    returns its path for use with requests' verify parameter.

    Returns:
        bool | str: Either True for system trust or a file path to a CA certificate

    Raises:
        No exceptions are raised by this function
    """
    # For HTTPS with self-signed certificates, disable verification for localhost
    if (
        CALENDAR_MCP_CA_CERT_B64
        and CALENDAR_MCP_CA_CERT_B64 != ""
        and CALENDAR_MCP_URL
        and CALENDAR_MCP_URL.startswith("https://")
        and "localhost" in CALENDAR_MCP_URL
    ):
        pem_bytes = base64.b64decode(CALENDAR_MCP_CA_CERT_B64)
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        tf.write(pem_bytes)
        tf.flush()
        tf.close()
        return tf.name

    # Default: use system trust (works with public certs such as from AWS ACM)
    return True


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

    session = requests.Session()

    # Only set up mTLS for HTTPS connections
    if CALENDAR_MCP_URL and CALENDAR_MCP_URL.startswith("https://"):
        if not CALENDAR_MCP_CLIENT_P12:
            raise RuntimeError(
                "CALENDAR_MCP_CLIENT_P12 is empty; provide base64 of the client .p12 (cert+key)."
            )

        try:
            p12_bytes = base64.b64decode(CALENDAR_MCP_CLIENT_P12)
        except Exception as e:
            raise RuntimeError("CALENDAR_MCP_CLIENT_P12 is not valid base64") from e

        adapter = Pkcs12Adapter(
            pkcs12_data=p12_bytes,
            pkcs12_password=(CALENDAR_MCP_CLIENT_P12_PASSWORD or ""),
        )
        session.mount(
            CALENDAR_MCP_URL,  # <-- Use base URL so the mTLS certs are not sent to other domains
            adapter,
        )

    # Keep legacy bearer & headers
    session.headers.update({
        "Authorization": f"Bearer {CALENDAR_BEARER_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return session
