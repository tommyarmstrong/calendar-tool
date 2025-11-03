import json
from typing import Any

from auth.google_oauth import finish_auth, start_auth_url
from shared_infrastructure.platform_manager import create_logger

logger = create_logger(logger_name="calendar-redirect", log_level="INFO")
logger.info("Starting Calendar OAuth Redirect Service")


def create_response(
    status_code: int,
    body: str,
    content_type: str = "text/plain",
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Create a standard HTTP response.

    Args:
        status_code (int): HTTP status code.
        body: Response body (str or dict).
        content_type (str, optional): Content-Type header. Defaults to "text/plain".
        headers (dict[str, str] | None, optional): Additional headers. Defaults to None.

    Returns:
        dict: Standardized response dictionary.
    """
    response_headers = {"Content-Type": content_type}
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": status_code,
        "body": body,
        "headers": response_headers,
        "isBase64Encoded": False,
    }


def process(event: dict[str, Any]) -> dict[str, Any]:
    """Process the incoming  HTTP Gateway event."""
    route_key = event.get("routeKey", "")
    method, _, route = route_key.partition(" ")

    logger.info(f"Processing request: {method} {route}")

    if not route:
        logger.error("No route found")
        return create_response(404, "Not Found")

    # --- Google OAuth flow routes -------------------------------
    if method == "GET" and route == "/oauth/start":
        logger.info("Starting OAuth flow")
        try:
            auth_url = start_auth_url()
            return create_response(302, "", headers={"Location": auth_url})
        except Exception as e:
            logger.error(f"OAuth start failed: {e}")
            return create_response(500, f"OAuth start failed: {e}")

    elif method == "GET" and route == "/oauth/callback":
        logger.info("OAuth callback received")
        query_params = event.get("queryStringParameters", {})
        code = query_params.get("code")
        error = query_params.get("error")

        if error:
            logger.error(f"OAuth error: {error}")
            return create_response(400, f"OAuth error: {error}")

        if not code:
            logger.error("Missing OAuth code")
            return create_response(400, "Missing code")

        try:
            finish_auth(code)
            logger.info("OAuth authentication completed successfully")
            return create_response(200, "Google connected ✅ You can close this tab.")
        except Exception as e:
            logger.error(f"OAuth callback failed: {e}")
            return create_response(500, f"OAuth callback failed: {e}")

    elif method == "GET" and route == "/healthz":
        logger.info("Health check requested")
        return create_response(200, json.dumps({"ok": True}), "application/json")

    # Default case for unmatched routes
    return create_response(404, "Route and method not Found")
