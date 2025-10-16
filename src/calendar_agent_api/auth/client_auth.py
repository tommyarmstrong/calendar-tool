from typing import Any

from app.config import CALENDAR_BEARER_TOKEN


def authorize_client_request(headers: dict[str, Any]) -> bool:
    """
    Check Bearer token authentication for Lambda events.
    """
    auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
    token = auth_header.split(" ", 1)[1]

    if token == CALENDAR_BEARER_TOKEN:
        return True
    return False
