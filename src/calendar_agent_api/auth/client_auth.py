from typing import Any

from app.config import X_CLIENT_ID, get_settings

settings = get_settings()


def authorize_client_request(headers: dict[str, Any]) -> list[str]:
    """
    Check Bearer token authentication for Lambda events.
    """
    # Extract bearer token from headers
    auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
    token = auth_header.split(" ", 1)[1]

    # Extract client ID from headers
    client_id = headers.get("x-client-id")

    authorization_issues = []
    if token != settings.calendar_bearer_token:
        authorization_issues.append(f"Invalid bearer token: {token} ")

    if client_id != X_CLIENT_ID:
        authorization_issues.append(f"Invalid client ID: {client_id} ")

    return authorization_issues
