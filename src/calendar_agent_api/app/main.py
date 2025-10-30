#!/usr/bin/env python3
import json
from typing import Any

from app.config import (
    INVOKE_LAMBDA_FILE,
    INVOKE_LAMBDA_NAME,
    X_CLIENT_ID,
    generate_request_id,
    get_settings,
)
from app.process_event import process_event_data
from auth.client_auth import authorize_client_request
from auth.slack_auth import authorize_slack_request, verify_slack_signature
from infrastructure.platform_manager import create_logger, invoke_lambda
from services.cache_service import RedisCache, status_update

settings = get_settings()
redis_host = settings.redis_host
redis_port = settings.redis_port
redis_password = settings.redis_password

assert redis_host is not None and redis_port is not None and redis_password is not None
cache = RedisCache(redis_host, int(redis_port), redis_password)


def create_slack_response() -> dict[str, str]:
    """
    Create a standard Slack response for acknowledgement, with status code 200 and body 'ok'.
    """
    return create_response(200, "ok")


def create_response(
    status_code: int, body: str, content_type: str = "text/plain"
) -> dict[str, Any]:
    """
    Create a standard HTTP response.
    """
    return {
        "statusCode": status_code,
        "body": body,
        "headers": {"Content-Type": content_type},
        "isBase64Encoded": False,
    }


def process(event: dict[str, Any]) -> dict[str, Any]:
    """
    Process the incoming HTTP Gateway event.
    """
    logger = create_logger("INFO")
    logger.info("Agent API lambda handler called")

    # Generate request_id
    request_id = generate_request_id()

    # Extract headers and body from the event and create the data for the Calendar Agent
    headers, body_json, agent_data = process_event_data(event, request_id)

    # 1. Handle Slack's initial API verification challenge
    if "Slack" in headers.get("user-agent", "") and "challenge" in body_json:
        logger.info("Returning Slack challenge")
        return create_response(200, json.dumps(body_json), "application/json")

    # 2a. Verify the Slack signature
    if headers.get("x-slack-signature"):
        logger.info("Slack request detected")
        body_raw = event.get("body", "")
        if not verify_slack_signature(body_raw, headers):
            # Return 200 to Slack to acknowledge receipt, but log the error
            # This prevents Slack from retrying the request
            logger.error("Invalid Slack signature")
            logger.error(f"Timestamp: {headers.get('x-slack-request-timestamp', '')}")
            logger.error(f"Slack signature: {headers.get('x-slack-signature', '')}")
            return create_slack_response()
        logger.info("Slack signature verified")

        # 2b. Authorize the Slack request
        authorization_issues = authorize_slack_request(agent_data)
        if authorization_issues:
            logger.error("Invalid Slack request")
            for issue in authorization_issues:
                logger.error(issue)
            return create_response(400, "Invalid Slack request")
        if not authorization_issues:
            logger.info("Slack request authorized")

    # 3. Validate Client requests
    if headers.get("x-client-id") == X_CLIENT_ID:
        # Validate the client request
        authorization_issues = authorize_client_request(headers)
        if authorization_issues:
            logger.error("Invalid client request")
            for issue in authorization_issues:
                logger.error(issue)
            return create_response(400, "Invalid client request")
        if not authorization_issues:
            logger.info("Client request authorized")
        # Update the status in the cache
        status_update(request_id=request_id, status_code="202", status="processing")

    # 4. Invoke the lambda function to process the message in a seperate thread
    logger.debug("Invoking Calendar Agent Lambda")
    logger.debug(f"Agent data: {agent_data}")
    logger.debug(f"Function name: {INVOKE_LAMBDA_NAME}")
    logger.debug(f"Handler file: {INVOKE_LAMBDA_FILE} (Unused in AWS deployment)")
    try:
        invoke_lambda(
            agent_data,
            function_name=INVOKE_LAMBDA_NAME,
            lambda_handler_filename=INVOKE_LAMBDA_FILE,  # <-- Unused in AWS deployment
        )
        logger.debug("Calendar Agent Invoked")
    except Exception as e:
        logger.error(f"Error invoking lambda function: {e}")
        return create_response(500, "Internal Server Error")

    # 5. Return the response
    # If post looks like it's from Slack, return 200 while processing in the background
    if headers.get("x-slack-signature"):
        return create_slack_response()

    # If post looks like it's from a Client, return 202 while processing in the background
    if headers.get("x-client-id") == X_CLIENT_ID:
        status_update_key = cache.get_status_key(request_id)
        data = {
            "message": "processing",
            "request_id": request_id,
            "status_update_key": status_update_key,
        }
        return create_response(202, json.dumps(data), "application/json")

    return create_response(400, "Unrecognized headers")
