from typing import Any

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


def post_to_slack(*, channel_id: str, slack_bot_token: str, message: str) -> dict[str, Any]:
    """Post a message to Slack using the bot token from secrets."""
    if not channel_id:
        error_msg = (
            "Argument 'channel_id' is not set. You must provide a channel ID to post to Slack."
        )
        return {"ok": False, "error": error_msg}
    if not message:
        error_msg = "Argument 'message' is not set. You must provide a message to post to Slack."
        return {"ok": False, "error": error_msg}

    try:
        token = slack_bot_token
        if not token:
            return {"ok": False, "error": "SLACK_PA_BOT_TOKEN not found in secrets"}
        client = WebClient(token=token)
        response = client.chat_postMessage(channel=channel_id, text=message)

        # Slack SDK returns a SlackResponse; convert minimal fields to dict-like for caller
        if response.get("ok"):
            return {
                "ok": True,
                "ts": response.get("ts"),
                "channel": response.get("channel"),
            }
        else:
            error_msg = f"Slack API error: {response.get('error')}"
            return {"ok": False, "error": error_msg}

    except SlackApiError as e:
        error_msg = f"Slack API error: {e.response.get('error', str(e)) if e.response else str(e)}"
        return {"ok": False, "error": error_msg}

    except Exception as e:
        error_msg = f"Exception while posting to Slack: {e}"
        return {"ok": False, "error": error_msg}
