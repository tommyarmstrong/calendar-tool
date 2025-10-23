import json
from typing import Any, cast

from app.config import settings
from auth.bearer_token_auth import check_authentication
from auth.google_oauth import finish_auth, start_auth_url
from infrastructure.platform_manager import create_logger
from mcp.manifest import manifest
from mcp.router import call_tool, list_tools
from mcp.schemas import LIST

logger = create_logger(logger_name="calendar-mcp", log_level="INFO")
logger.info("Starting Calendar MCP Service")


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
    logger.info(f"Event: {event}")

    if not route:
        return create_response(404, "Not Found")

    # Check authentication for MCP routes (routes tht begin with "/mcp/")
    # TODO: This should not use the bearer token auth. Use the OAuth flow and/or sit behind mTLS

    if route.startswith("/mcp/"):
        try:
            check_authentication(event)
            logger.info("Authentication successful")
        except Exception as e:
            logger.warning(f"Authentication failed: {e}")
            return create_response(401, str(e))

    if method == "GET" and route == "/mcp/.well-known/mcp/manifest":
        logger.info("Returning manifest")
        return create_response(
            200, json.dumps(manifest(settings.calendar_mcp_url)), "application/json"
        )

    elif method == "GET" and route == "/mcp/schemas":
        logger.info("Returning schemas")
        return create_response(200, json.dumps(LIST), "application/json")

    elif method == "GET" and route == "/mcp/tools":
        logger.info("Returning tools")
        return create_response(200, json.dumps({"tools": list_tools()}))

    elif method == "POST" and route == "/mcp/tools/call":
        logger.info("Tools call received")
        body = event.get("body", {})
        if not body:
            return create_response(400, "Missing body")

        if isinstance(body, bytes) or isinstance(body, str):
            body = json.loads(body)

        name = body.get("name")
        if not name:
            return create_response(400, "Missing tool name")

        args = body.get("arguments", {})
        if not isinstance(args, dict):
            args = json.loads(args)
            if not isinstance(args, dict):
                return create_response(400, "Invalid arguments")

        # Ensure args is properly typed as dict[str, Any]
        args_dict = cast(dict[str, Any], args)

        try:
            result = call_tool(name, args_dict)
            error = result.get("error")
            if error:
                logger.error(f"{error.get('code')} {error.get('message')}")
            return create_response(200, json.dumps(result), "application/json")

        except Exception as e:
            raise (e) from e

    # --- OAuth flow -------------------------------

    elif method == "GET" and route == "/oauth/start":
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
