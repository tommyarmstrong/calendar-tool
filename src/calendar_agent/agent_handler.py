from typing import Any

from app.main import process


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entry point for Calendar Agent."""
    try:
        result = process(event)
        # Type assertion: process() returns dict[str, Any] as declared
        assert isinstance(result, dict)
        return result
    except Exception as e:
        import traceback

        traceback.print_exc()
        raise Exception(f"Error in processing Calendar Agent: {e}") from e


# Change 1: Testing integration of Github and AWS with minor code change.
# Change 2
# Change 3
# Change 4
# Change 5
# Change 6
