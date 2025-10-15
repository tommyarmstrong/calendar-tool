import json
from typing import Any

from app.config import settings
from auth.bearer_token_auth import check_authentication
from infrastructure.platform_manager import create_logger
from mcp.manifest import manifest
from mcp.router import call_tool, list_tools
from mcp.schemas import LIST

logger = create_logger(logger_name="calendar-mcp", log_level="INFO")
logger.info("Starting Calendar MCP Service")


def create_response(
    status_code: int, body: str, content_type: str = "text/plain"
) -> dict[str, Any]:
    """
    Create a standard HTTP response.

    Args:
        status_code (int): HTTP status code.
        body: Response body (str or dict).
        content_type (str, optional): Content-Type header. Defaults to "text/plain".

    Returns:
        dict: Standardized response dictionary.
    """
    return {
        "statusCode": status_code,
        "body": body,
        "headers": {"Content-Type": content_type},
        "isBase64Encoded": False,
    }


def process(event: dict[str, Any]) -> dict[str, Any]:
    """Process the incoming  HTTP Gateway event."""
    route_key = event.get("routeKey", "")
    method, _, route = route_key.partition(" ")

    if not route:
        return create_response(404, "Not Found")

    # Check authentication for MCP routes (routes tht begin with "/mcp/")
    if route.startswith("/mcp/"):
        try:
            check_authentication(event)
            logger.info("Authentication successful")
        except Exception as e:
            logger.warning(f"Authentication failed: {e}")
            return create_response(401, str(e))

    if method == "GET" and route == "/.well-known/mcp/manifest":
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

        try:
            result = call_tool(name, args)
            error = result.get("error")
            if error:
                logger.error(f"{error.get('code')} {error.get('message')}")
            return create_response(200, json.dumps(result), "application/json")

        except Exception as e:
            raise (e) from e

    # Default case for unmatched routes
    return create_response(404, "Route and method not Found")
