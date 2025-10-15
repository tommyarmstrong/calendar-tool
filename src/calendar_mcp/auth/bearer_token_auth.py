from typing import Any

from app.config import settings


def check_authentication(event: dict[str, Any]) -> None:
    """
    Check Bearer token authentication for Lambda events.

    Args:
        event: Lambda event dictionary containing headers.

    Raises:
        Exception: If authentication fails.
    """
    if not settings.calendar_bearer_token:
        raise Exception("Unauthorized: MCP bearer token not set")

    headers = event.get("headers", {})
    auth_header = headers.get("authorization", "") or headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        raise Exception("Unauthorized: Missing or invalid Bearer token")

    token = auth_header.split(" ", 1)[1]
    if token != settings.calendar_bearer_token:
        raise Exception("Unauthorized: Invalid Bearer token")
