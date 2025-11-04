import json
from typing import Any, cast

from app.config import get_settings
from auth.hmac_auth import verify_hmac_signature
from infrastructure.platform_manager import create_logger
from infrastructure.redis_manager import build_redis_manager
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

    settings = get_settings()
    redis_manager = build_redis_manager(settings.redis_url)

    # Get the route key and split it into method and route
    route_key = event.get("routeKey", "")
    method, _, route = route_key.partition(" ")
    logger.info(f"Processing request: {method} {route}")

    if not route:
        logger.error("No route found")
        return create_response(404, "Not Found")

    if method not in ["GET", "POST"]:
        logger.error("Invalid method")
        return create_response(404, "Not Found")

    # Get the headers and body from the event
    body = event.get("body", {})
    headers = event.get("headers", {})
    timestamp = headers.get("x-agent-timestamp", "")
    nonce = headers.get("x-agent-nonce", "")
    signature = headers.get("x-agent-signature", "")

    if not timestamp or not nonce or not signature:
        logger.error("Missing HMAC headers")
        return create_response(401, "Missing HMAC headers")

    # Check the nonce is unique
    if not redis_manager.is_nonce_unique(nonce):
        logger.error("HMAC nonce not unique")
        return create_response(401, "Nonce not unique")

    # Validate the HMAC signature
    is_valid, reason = verify_hmac_signature(
        ts_str=timestamp,
        nonce=nonce,
        method=method,
        path_only=route,
        body=body,
        provided_sig_b64=signature,
        secret=settings.agent_hmac_secret,
    )

    if not is_valid:
        logger.error(f"Invalid HMAC signature: {reason}")
        return create_response(401, f"Invalid HMAC signature: {reason}")
    else:
        logger.info("HMAC signature validated")

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

        # Ensure args is properly typed as dict[str, Any]
        args_dict = cast(dict[str, Any], args)

        try:
            result = call_tool(name, args_dict)
            error = result.get("error")
            if error:
                logger.error(f"{error.get('code')}: {error.get('message')}")
            return create_response(200, json.dumps(result), "application/json")

        except Exception as e:
            raise (e) from e

    # Default case for unmatched routes
    return create_response(404, "Route and method not Found")
