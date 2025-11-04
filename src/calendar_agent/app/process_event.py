from typing import Any

from app.config import X_CLIENT_ID, get_settings
from infrastructure.redis_manager import build_redis_manager


def validate_data(data: dict[str, Any]) -> bool:
    """Validate the event data."""
    request_type = data.get("request_type")

    # All events should have a request_id added by the API Gateway
    if not data.get("request_id") or not isinstance(data.get("request_id"), str):
        raise ValueError("No request_id provided in the request")

    # All events should have a message
    if not data.get("message") or not isinstance(data.get("message"), str):
        raise ValueError("No message provided")

    # All events should have a request_type of either 'client' or 'slack'
    if request_type != "client" and request_type != "slack":
        raise ValueError("Unknown client type")

    # All client events should have a valid client ID
    if request_type == "client" and (data.get("client_id") != X_CLIENT_ID):
        raise ValueError("Invalid client ID")

    # All Slack events should have a channel_id
    if request_type == "slack" and not data.get("channel_id"):
        raise ValueError("No channel_id provided in the Slack request")

    # All Slack events should have a bot_user_id
    if data.get("slack_signature") and not data.get("bot_user_id"):
        raise ValueError("No bot_user_id provided in the Slack request")

    # All Slack events should have a user_id
    if request_type == "slack" and not data.get("user_id"):
        raise ValueError("No user_id provided in the request")

    return True


def process_event_data(event: dict[str, Any]) -> dict[str, Any]:
    """Process the event data."""
    data: dict[str, Any] = event.get("payload", {})

    try:
        validate_data(data)
        return data
    except ValueError as e:
        settings = get_settings()
        redis_manager = build_redis_manager(settings.redis_url)
        request_id = data.get("request_id")
        if request_id:
            redis_manager.set_json(
                redis_manager.get_status_key(request_id),
                {"status_code": 400, "message": str(e)},
                ttl=15 * 60,
            )
        raise ValueError(f"Invalid data: {e}") from e
    except Exception as e:
        settings = get_settings()
        redis_manager = build_redis_manager(settings.redis_url)
        request_id = data.get("request_id")
        if request_id:
            redis_manager.set_json(
                redis_manager.get_status_key(request_id),
                {"status_code": 500, "message": "Internal Server Error"},
                ttl=15 * 60,
            )
        raise ValueError(f"Invalid data: {e}") from e
