import json
import re
import time
from typing import Any


def process_event_data(
    event: dict[str, Any], request_id: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Process the event data."""
    # Extract headers
    headers = event.get("headers", {})

    body_raw = event.get("body", "")
    # AWS API Gateway sends body as a string but FastAPI sends as bytes
    assert isinstance(body_raw, str | bytes)
    try:
        # Slack signature verification requires the raw bytes
        # but also parse JSON for easier processing
        if isinstance(body_raw, bytes):
            body_json = json.loads(body_raw.decode('utf-8'))
        else:
            body_json = json.loads(body_raw)
    except json.JSONDecodeError:
        body_json = {}
    except Exception as e:
        raise ValueError(f"Error parsing body: {e}") from e

    # Generate the data for the Calendar Agent
    # Ensure body_json is a dictionary and type it properly
    if not isinstance(body_json, dict):
        body_json = {}

    body_json_dict: dict[str, Any] = body_json  # Type assertion to help the type checker
    agent_payload = _generate_agent_payload(headers, body_json_dict, request_id)
    agent_data = _generate_agent_data(event, agent_payload)

    return headers, body_json, agent_data


def _get_bot_id(body_json: dict[str, Any]) -> str:
    # Bot ID
    authorizations = body_json.get("authorizations", []) or []
    bot_user_id = ""
    for auth in authorizations:
        if auth.get("is_bot"):
            bot_user_id = auth.get("user_id")
            assert isinstance(bot_user_id, str)
            break

    if bot_user_id:
        return bot_user_id
    return ""


def _get_event_messsage(event: dict[str, Any]) -> str:
    # Extract the message from the Slack event
    raw_text = event.get("text")  # e.g. "<@U09KXC8V0M8> Am I free on Friday?"

    # Remove the first leading @mention token if present (common for app_mention)
    message = None
    if isinstance(raw_text, str):
        message = re.sub(r"^<@[^>]+>\s*", "", raw_text).strip()

    if message:
        return message
    return ""


def _generate_agent_payload(
    headers: dict[str, Any], body_json: dict[str, Any], request_id: str
) -> dict[str, Any]:
    """Generate an event dictionary for the Agent Lambda function."""

    # Process Slack events
    if headers.get("x-slack-signature"):
        event = body_json.get("event", {})
        return {
            "request_type": "slack",
            "request_id": request_id,
            "user_id": str(event.get("user", "")),
            "channel_id": str(event.get("channel", "")),
            "bot_user_id": _get_bot_id(body_json),
            "message": _get_event_messsage(event),
        }

    # Process Client events
    elif headers.get("x-client-id"):
        return {
            "request_type": "client",
            "request_id": request_id,
            "client_id": headers.get("x-client-id"),
            "message": body_json.get("message"),
        }

    # Unsupported client types should not happen
    else:
        raise ValueError("Unsupported client type")


def _generate_agent_data(event: dict[str, Any], agent_payload: dict[str, Any]) -> dict[str, Any]:
    """Generate the data for the agent."""
    # Auth already enforced by API GW authorizer or here.
    authz = event.get("requestContext", {}).get("authorizer", {}).get("lambda", {})
    principal_id = authz.get("principalId", "anonymous")

    # Generate the data for the agent
    return {
        "schema_version": "1.0",
        "request_id": event.get("requestContext", {}).get("requestId"),
        "request_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": {
            "route": event.get("routeKey"),
            "method": event.get("requestContext", {}).get("http", {}).get("method"),
            "path": event.get("requestContext", {}).get("http", {}).get("path"),
        },
        "actor": {
            "principal_id": principal_id,
            "scopes": authz.get("scopes", ""),
            "tenant": authz.get("tenant", ""),
        },
        "payload": agent_payload,
        # "idempotency_key": headers.get("idempotency-key")
    }
