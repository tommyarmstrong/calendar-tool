import logging
from typing import Any


def log_plan_response(plan_response: dict[str, Any], logger: logging.Logger) -> None:
    logger.info(f"Plan created by model: {plan_response.get('model_version', 'Unknown')}")
    logger.info(f"Usage: {plan_response.get('usage', 'Unknown')}")
    logger.info(f"Plan name: {plan_response.get('tool_name', 'Unknown')}")
    logger.info(f"Arguments: {plan_response.get('tool_arguments', 'Unknown')}")
