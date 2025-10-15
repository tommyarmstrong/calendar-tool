#!/usr/bin/env python3
# podcast_chat_api.py
import json
import uuid
from typing import Any

from infrastructure.platform_manager import create_logger, get_parameters, invoke_lambda
from services.cache_service import RedisCache
from slack_sdk.signature import SignatureVerifier

""" Constants """
secrets = get_parameters(
    ["slack_pa_signing_secret", "redis_password"], "/apps/prod/secrets/", decrypt=True
)

SLACK_PA_SIGNING_SECRET = secrets["slack_pa_signing_secret"]
REDIS_PASSWORD = secrets["redis_password"]

infra_params = get_parameters(["redis_host", "redis_port"], "/apps/prod/infra/")

REDIS_HOST = infra_params["redis_host"]
REDIS_PORT = infra_params["redis_port"]

INVOKE_LAMBDA_NAME = "calendar_agent"
X_CLIENT_ID = "dev-test-client-v1"

# Validate configuration values
for k, v in {
    "INVOKE_LAMBDA_NAME": INVOKE_LAMBDA_NAME,
    "REDIS_HOST": REDIS_HOST,
    "REDIS_PORT": REDIS_PORT,
    "REDIS_PASSWORD": REDIS_PASSWORD,
    "SLACK_PA_SIGNING_SECRET": SLACK_PA_SIGNING_SECRET,
    "X_CLIENT_ID": X_CLIENT_ID,
}.items():
    if not v:
        raise ValueError(f"Configuration value is invalid: {k}")


def create_slack_response() -> dict[str, str]:
    """
    Create a standard Slack response for acknowledgement.

    Returns:
        dict: Standard Slack response with status code 200 and body 'ok'.
    """
    return create_response(200, "ok")


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


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Lambda handler for the Calendar Agent API. Handles Slack and client events,
    verifies signatures, and invokes the Agent processor Lambda.

    Args:
        event (dict): Lambda event data, expects 'body' and 'headers'.
        context: Lambda context object (unused).

    Returns:
        dict: API Gateway-compatible response with status code and message.
    """
    logger = create_logger("INFO")
    logger.info("API lambda handler called")

    # API Gateway sends body as a string in event['body'], FastAPI sends as bytes
    body_raw = event.get("body", "")
    try:
        # If body is a string or bytes, attempt to decode as JSON
        if isinstance(body_raw, str | bytes):
            # For Slack signature verification, we need to keep the raw bytes
            # but also parse JSON for processing
            if isinstance(body_raw, bytes):
                body_json = json.loads(body_raw.decode('utf-8'))
            else:
                body_json = json.loads(body_raw)
        elif isinstance(body_raw, dict):
            body_json = body_raw  # Possibly pre-parsed during testing
        else:
            body_json = {}
    except json.JSONDecodeError:
        body_json = {}

    # Extract headers
    headers = event.get("headers", {})

    # Handle Slack's initial API verification challenge
    if "Slack" in headers.get("user-agent", "") and "challenge" in body_json:
        logger.info("Returning Slack challenge")
        return create_response(200, json.dumps(body_json), "application/json")

    if headers.get("x-slack-signature"):
        # Confirm that the Slack signing secret is configured
        if not SLACK_PA_SIGNING_SECRET:
            system_msg = (
                "Post has Slack headers but SLACK_PA_BOT_SIGNING_SECRET is not configured. "
                "Cannot verify Slack signature."
            )
            logger.error(system_msg)
            # Return 200 to Slack to acknowledge receipt, but log the error
            # This prevents Slack from retrying the request
            return create_slack_response()

        # Ensure body_raw is in bytes for Slack signature verification
        if isinstance(body_raw, str):
            body_raw = body_raw.encode('utf-8')

        if not isinstance(body_raw, bytes):
            system_msg = "Expecting string or bytes for Slack signature verification."
            logger.error(system_msg)
            # Return 200 to Slack to acknowledge receipt, but log the error
            # This prevents Slack from retrying the request
            return create_slack_response()

        # Verify Slack request (use raw body passed by Slack, not the parsed JSON)
        verifier = SignatureVerifier(SLACK_PA_SIGNING_SECRET)
        # Ensure body_raw is the correct type for verification
        if not verifier.is_valid_request(body_raw, headers):
            error_msg = "Invalid Slack signature"
            logger.error(error_msg)
            logger.error(
                f'Headers:x-slack-request-timestamp: {headers.get("x-slack-request-timestamp", "")}'
            )
            logger.error(f'Headers: x-slack-signature: {headers.get("x-slack-signature", "")}')
            # Return 200 to Slack to acknowledge receipt, but log the error
            # This prevents Slack from retrying the request
            return create_slack_response()

    # Create a request ID and add it to the event / body data
    request_id = str(uuid.uuid4())
    if isinstance(body_json, dict):
        body_json["request_id"] = request_id
        event["body"] = body_json
    else:
        # Handle case where body_json is not a dict
        event["body"] = {"request_id": request_id}

    # Invoke the lambda function to process the message in a seperate thread
    try:
        invoke_lambda(event, function_name=INVOKE_LAMBDA_NAME)
        logger.info("Calendar Agent Invoked")
    except Exception as e:
        logger.error(f"Error invoking lambda function: {e}")
        return create_response(500, "Internal Server Error")

    # If post looks like it's from Slack, return 200 while processing
    # continues in background
    if headers.get("x-slack-signature"):
        return create_slack_response()

    # If post looks like it's from a Client, return 202 while
    # processing continues in background
    if headers.get("x-client-id") == X_CLIENT_ID:
        # Add request_id to cache
        assert REDIS_HOST is not None and REDIS_PORT is not None and REDIS_PASSWORD is not None
        cache = RedisCache(REDIS_HOST, int(REDIS_PORT), REDIS_PASSWORD)
        status_update_key = cache.get_status_key(request_id)
        cache.set_json(
            status_update_key, {"status_code": 202, "message": "processing"}, ttl=15 * 60
        )

        data = {
            "message": (
                f"Client post accepted (processing) | status available at /status/{request_id}"
            ),
            "status_update_key": status_update_key,
        }
        return create_response(202, json.dumps(data), "application/json")
    return create_response(400, "Unrecognized headers")
