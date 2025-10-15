from collections.abc import Sequence
from typing import Any, Protocol

class Response(Protocol):
    output_text: str | None
    output: list[Any]
    usage: Any
    model: str
    error: Any | None
    incomplete_details: Any | None

class Responses:
    def create(
        self,
        *,
        model: str,
        input: Sequence[dict[str, Any]],
        max_output_tokens: int | None = None,
        text: dict[str, Any] | None = None,
        reasoning: dict[str, Any] | None = None,
        tool_choice: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> Response: ...

class OpenAI:
    def __init__(self, *, api_key: str) -> None: ...
    responses: Responses
