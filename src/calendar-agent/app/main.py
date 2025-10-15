import json
from typing import Any

from app.config import REDIS_HOST, REDIS_PASSWORD, REDIS_PORT, SLACK_PA_BOT_TOKEN
from app.logging import log_plan_response
from app.process_event import process_event_data
from infrastructure.platform_manager import create_logger
from infrastructure.slack_manager import post_to_slack
from services.cache_service import RedisCache
from services.llm_service import plan_mcp_call
from services.mcp_client_service import call_mcp
from services.renderer_service import render_mcp_result
from services.validate_slack_user import validate_slack_user

logger = create_logger(logger_name="calendar-agent", log_level="INFO")
logger.info("Starting Calendar Agent")


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


def process(event: dict[str, Any]) -> dict[str, Any]:
    """Process the incoming HTTP Gateway event."""

    # Process the event data
    try:
        data = process_event_data(event)
        logger.info("User message recieved.")
    except ValueError as e:
        logger.error(e)
        return create_response(status_code=400, body=str(e), content_type="text/plain")
    except Exception as e:
        logger.error(e)
        return create_response(status_code=400, body=str(e), content_type="text/plain")

    # If the post came from Slack, check if the user is allowed to use the agent
    if data.get("slack_signature"):
        try:
            validate_slack_user(data)
        except ValueError as e:
            logger.error(e)
            return create_response(status_code=400, body=str(e), content_type="text/plain")

    # Plan the MCP call and log the details
    try:
        plan_response = plan_mcp_call(data["message"])
        tool_name = plan_response.get("tool_name", "")
        arguments: dict[str, Any] = plan_response.get("tool_arguments", {})
        log_plan_response(plan_response, logger)
    except ValueError as e:
        logger.error(f"Invalid request: {e}")
        return create_response(
            status_code=400, body=f"Invalid request: {e}", content_type="text/plain"
        )
    except RuntimeError as e:
        logger.error(f"LLM error: {e}")
        return create_response(
            status_code=500, body=f"AI model error: {e}", content_type="text/plain"
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return create_response(
            status_code=500,
            body=f"Internal server error: {e}",
            content_type="text/plain",
        )

    # Call the MCP tool
    result = call_mcp(tool_name, arguments)
    if not result:
        error_message = f"MCP did not return a result: {result}"
        logger.error(error_message)
        return create_response(status_code=400, body=error_message, content_type="text/plain")

    # Render the result as a string
    result_string = render_mcp_result(result)
    logger.info(f"Result: {result_string}")

    # Post the result to the cache if the post came from a client (not Slack)
    if data.get("client_id"):
        assert REDIS_HOST is not None, "REDIS_HOST is not configured"
        assert REDIS_PORT is not None, "REDIS_PORT is not configured"
        assert REDIS_PASSWORD is not None, "REDIS_PASSWORD is not configured"
        status = {"status_code": 200, "message": result}

        cache = RedisCache(REDIS_HOST, int(REDIS_PORT), REDIS_PASSWORD)
        status_update_key = cache.get_status_key(data["request_id"])
        cache.set_json(status_update_key, status, ttl=15 * 60)

    # Post the result to Slack channel if the post came from Slack
    if data.get("slack_signature"):
        assert SLACK_PA_BOT_TOKEN is not None, "SLACK_PA_BOT_TOKEN is not configured"
        response = post_to_slack(
            channel_id=data["channel_id"],
            slack_bot_token=SLACK_PA_BOT_TOKEN,
            message=result_string,
        )
        logger.info(f"Slack response: {response}")

    # Basic response for now
    lambda_response = create_response(
        status_code=200, body=json.dumps(result), content_type="text/plain"
    )
    return lambda_response
