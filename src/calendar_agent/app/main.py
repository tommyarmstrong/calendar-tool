import json
from typing import Any

from app.config import SLACK_PA_BOT_TOKEN
from app.logging import log_plan_response
from app.process_event import process_event_data
from infrastructure.platform_manager import create_logger
from infrastructure.slack_manager import post_to_slack
from services.cache_service import status_update
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
    status_code, result_string = render_mcp_result(result)
    logger.info(f"Result: {result_string}")

    # Post the result to the cache if the post came from a client (not Slack)
    if data.get("request_type") == "client":
        request_id = data.get("request_id")
        if not request_id:
            logger.error("Client request without a request_id: cannot update status")
            return create_response(
                status_code=400,
                body="Missing request_id: cannot update status",
                content_type="text/plain",
            )

        status_update(request_id=request_id, status_code=status_code, status=result_string)

    # Post the result to Slack channel if the post came from Slack
    if data.get("request_type") == "slack":
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
