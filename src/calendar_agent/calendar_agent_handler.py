from typing import Any

from app.main import process


def agent_lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entry point for Calendar Agent."""
    try:
        result = process(event)
        return result  # type: ignore[no-any-return]
    except Exception as e:
        import traceback

        traceback.print_exc()
        raise Exception(f"Error in processing Calendar Agent: {e}") from e
