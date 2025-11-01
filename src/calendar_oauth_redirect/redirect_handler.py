from typing import Any

from app.main import process


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entry point for Calendar OAuth Redirect."""
    try:
        result = process(event)
        # Type assertion: process() returns dict[str, Any] as declared
        assert isinstance(result, dict)
        return result
    except Exception as e:
        raise Exception(f"Error in processing Calendar OAuth Redirect: {e}") from e


# Change 1: Test the changes to CI/CD pipeline
