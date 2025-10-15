import json
import re
from typing import Any

from app.config import REDIS_HOST, REDIS_PASSWORD, REDIS_PORT, X_CLIENT_ID
from services.cache_service import RedisCache


def validate_data(data: dict[str, Any]) -> bool:
    """Validate the event data."""
    # All events should have a request_id added by the API Gateway
    if not data["request_id"] or not isinstance(data["request_id"], str):
        raise ValueError("No request_id provided in the request")

    # All events should have a message
    if not data["message"] or not isinstance(data["message"], str):
        raise ValueError("No message provided")

    # All events should have a client_id or slack_signature
    if not data["client_id"] and not data["slack_signature"]:
        raise ValueError("Unsupported client type")

    # All client events should have a valid client ID
    if data["client_id"] and data["client_id"] != X_CLIENT_ID:
        raise ValueError("Invalid client ID")

    # All Slack events should have a channel_id
    if data["slack_signature"] and not data["channel_id"]:
        raise ValueError("No channel_id provided in the Slack request")

    # All Slack events should have a bot_user_id
    if data["slack_signature"] and not data["bot_user_id"]:
        raise ValueError("No bot_user_id provided in the Slack request")

    # All Slack events should have a user_id
    if data["slack_signature"] and not data["user_id"]:
        raise ValueError("No user_id provided in the request")

    return True


def process_event_data(event: dict[str, Any]) -> dict[str, Any]:
    """Process the event data."""
    data: dict[str, Any] = {}

    # Extract the body
    body = event.get("body", {})
    if isinstance(body, str):
        body = json.loads(body)
    if not body or not isinstance(body, dict):
        raise ValueError("No body provided in the request")

    # All events should have a request_id added to body by the API Gateway
    data["request_id"] = body.get("request_id")

    # Extract the headers. These can be a Starlette Headers object, a dict, or a JSON string.
    try:
        from starlette.datastructures import Headers as StarletteHeaders
    except Exception:  # if not running under Starlette
        StarletteHeaders = tuple()  # sentinel that'll never match

    def _get_headers(event: dict[str, Any]) -> dict[str, str]:
        raw = event.get("headers")
        if raw is None:
            raise ValueError("No headers provided in the request")

        if isinstance(raw, StarletteHeaders):  # Convert Starlette Headers -> dict
            return dict(raw.items())

        if isinstance(raw, dict):  # Already a dict
            return raw

        if isinstance(raw, str):  # JSON string
            return dict(json.loads(raw))

        raise TypeError(f"Unsupported headers type: {type(raw)}")  # Anything else is unexpected

    headers = _get_headers(event)

    # Find the client type
    data["client_id"] = headers.get("x-client-id")
    data["slack_signature"] = headers.get("x-slack-signature")

    # Extract the required data for a client event
    if data["client_id"]:
        data["message"] = body.get("message")

    # Extract the required data for a Slack event
    if data["slack_signature"]:
        bodyevent = body.get("event", {})
        data["user_id"] = bodyevent.get("user")
        data["channel_id"] = bodyevent.get("channel")

        # Bot ID
        authorizations = body.get("authorizations", []) or []
        data["bot_user_id"] = None
        for auth in authorizations:
            if auth.get("is_bot"):
                data["bot_user_id"] = auth.get("user_id")
                break

        # Extract the message from the Slack event
        ev = body.get("event", {}) or {}
        raw_text = ev.get("text")  # e.g. "<@U09KXC8V0M8> Am I free on Friday?"

        # Remove the first leading @mention token if present (common for app_mention)
        message = None
        if isinstance(raw_text, str):
            message = re.sub(r"^<@[^>]+>\s*", "", raw_text).strip()
        data["message"] = message

    # Validate the data
    try:
        validate_data(data)
        return data
    except ValueError as e:
        assert REDIS_HOST is not None
        assert REDIS_PORT is not None
        assert REDIS_PASSWORD is not None
        cache = RedisCache(REDIS_HOST, int(REDIS_PORT), REDIS_PASSWORD)
        request_id = data.get("request_id")
        if request_id:
            cache.set_json(
                cache.get_status_key(request_id),
                {"status_code": 400, "message": str(e)},
                ttl=15 * 60,
            )
        raise ValueError(f"Invalid data: {e}") from e
    except Exception as e:
        assert REDIS_HOST is not None
        assert REDIS_PORT is not None
        assert REDIS_PASSWORD is not None
        cache = RedisCache(REDIS_HOST, int(REDIS_PORT), REDIS_PASSWORD)
        request_id = data.get("request_id")
        if request_id:
            cache.set_json(
                cache.get_status_key(request_id),
                {"status_code": 500, "message": "Internal Server Error"},
                ttl=15 * 60,
            )
        raise ValueError(f"Invalid data: {e}") from e
