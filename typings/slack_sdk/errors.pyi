from typing import Any

class SlackApiError(Exception):
    response: dict[str, Any] | None
