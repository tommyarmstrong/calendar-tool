from typing import Any

from app.config import get_settings
from slack_sdk.signature import SignatureVerifier

settings = get_settings()


def verify_slack_signature(body_raw: str | bytes, headers: dict[str, str]) -> bool:
    """Verify the Slack signature."""

    # Ensure body_raw is in bytes for Slack signature verification
    if isinstance(body_raw, str):
        body_raw = body_raw.encode('utf-8')

    # Verify Slack request (use raw body passed by Slack, not the parsed JSON)
    assert settings.slack_pa_signing_secret is not None  # Should alreadybe validated in config.py
    verifier = SignatureVerifier(settings.slack_pa_signing_secret)
    # Ensure body_raw is the correct type for verification
    if verifier.is_valid_request(body_raw, headers):
        return True
    return False


def authorize_slack_request(data: dict[str, Any]) -> list[str]:
    """Validate the Slack user."""
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    bot_user_id = data.get("bot_user_id")

    authorization_issues = []
    if user_id != settings.slack_pa_allowed_users:
        authorization_issues.append(f"Slack user is not authorized: {user_id} ")

    if channel_id != settings.slack_pa_allowed_channels:
        authorization_issues.append(f"Slack channel is not authorized: {channel_id} ")

    if bot_user_id != settings.slack_pa_allowed_bot:
        authorization_issues.append(f"Slack bot is not authorized: {bot_user_id} ")

    if authorization_issues:
        return authorization_issues
    return []
