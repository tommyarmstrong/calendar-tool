from typing import Any

from app.config import (
    SLACK_PA_ALLOWED_BOT,
    SLACK_PA_ALLOWED_CHANNELS,
    SLACK_PA_ALLOWED_USERS,
)


def validate_slack_user(data: dict[str, Any]) -> None:
    """Validate the Slack user."""
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    bot_user_id = data.get("bot_user_id")

    if user_id != SLACK_PA_ALLOWED_USERS:
        raise ValueError("User is not allowed to use the agent")

    if channel_id != SLACK_PA_ALLOWED_CHANNELS:
        raise ValueError("Channel is not allowed to use the agent")

    if bot_user_id != SLACK_PA_ALLOWED_BOT:
        raise ValueError("Bot is not allowed to use the agent")
