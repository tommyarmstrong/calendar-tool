from app.config import SLACK_PA_SIGNING_SECRET
from slack_sdk.signature import SignatureVerifier


def verify_slack_signature(body_raw: str | bytes, headers: dict[str, str]) -> bool:
    """Verify the Slack signature."""

    # Ensure body_raw is in bytes for Slack signature verification
    if isinstance(body_raw, str):
        body_raw = body_raw.encode('utf-8')

    # Verify Slack request (use raw body passed by Slack, not the parsed JSON)
    assert SLACK_PA_SIGNING_SECRET is not None  # Should alreadybe validated in config.py
    verifier = SignatureVerifier(SLACK_PA_SIGNING_SECRET)
    # Ensure body_raw is the correct type for verification
    if verifier.is_valid_request(body_raw, headers):
        return True
    return False
