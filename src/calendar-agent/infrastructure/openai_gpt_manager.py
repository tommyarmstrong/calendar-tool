import random
import time
from email.utils import parsedate_to_datetime
from typing import Any, Protocol, cast

from openai import OpenAI

from app.config import OPENAI_API_KEY
from infrastructure.data_models import Message


# Define response type directly because pyright is not correctly understanding the new GPT 5 API
class Response(Protocol):
    output_text: str | None
    output: list[Any]
    usage: Any
    model: str
    error: Any | None
    incomplete_details: Any | None


# Default configuration constants for GPT-5
DEFAULT_MAX_OUTPUT_TOKENS_GPT5 = 1000
DEFAULT_REASONING_EFFORT = "low"
DEFAULT_VERBOSITY = "low"
DEFAULT_TOOL_CHOICE = "auto"
# Shared configuration constants
DEFAULT_MAX_ATTEMPTS = 2
DEFAULT_RETRY_DELAY = 1.0


def _setup_retryable_errors() -> tuple[type[Exception], ...]:
    """
    Return error classes that are safe to retry.
    Based on OpenAI guidance: retry 429/rate limit, network timeouts, and 5xx.
    """
    try:
        import openai

        RateLimitError = getattr(openai, "RateLimitError", None)
        APIConnectionError = getattr(openai, "APIConnectionError", None)
        APITimeoutError = getattr(openai, "APITimeoutError", None)
        InternalServerError = getattr(openai, "InternalServerError", None)
        ServiceUnavailableError = getattr(openai, "ServiceUnavailableError", None)
    except ImportError:
        RateLimitError = APIConnectionError = APITimeoutError = InternalServerError = (
            ServiceUnavailableError
        ) = None

    retryable = [TimeoutError]  # local/python timeout safeguard
    for cls in (
        RateLimitError,
        APIConnectionError,
        APITimeoutError,
        InternalServerError,
        ServiceUnavailableError,
    ):
        if cls:
            retryable.append(cls)
    return tuple(retryable)


def _retry_sleep_seconds_from_headers(err: Exception) -> float | None:
    """
    Inspect the exception for rate-limit/Retry-After headers and return
    an absolute number of seconds to sleep. Returns None if no guidance.
    """
    resp = getattr(err, "response", None)
    headers = getattr(resp, "headers", None) or {}
    if not headers:
        return None

    def get_header(name: str) -> str | None:
        return headers.get(name) or headers.get(name.lower())

    # 1) Honor Retry-After if present (seconds OR HTTP-date)
    retry_after = get_header("Retry-After")
    if retry_after:
        retry_after = retry_after.strip()
        # Numeric seconds
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass
        # HTTP-date
        try:
            dt = parsedate_to_datetime(retry_after)
            return max(0.0, (dt.timestamp() - time.time()))
        except Exception:
            pass

        # 2) Use the later of the reset timestamps (epoch seconds)
        resets = []
        for key in ("x-ratelimit-reset-requests", "x-ratelimit-reset-tokens"):
            header_value = get_header(key)
            if not header_value:
                continue
            try:
                # Many gateways send epoch seconds (float/int as string)
                resets.append(float(header_value) - time.time())
            except ValueError:
                # If it’s an HTTP-date (rare), try to parse
                try:
                    dt = parsedate_to_datetime(header_value)
                    resets.append(dt.timestamp() - time.time())
                except Exception:
                    pass

        if resets:
            valid_resets = [r for r in resets if isinstance(r, int | float)]
            return max(0.0, max(valid_resets, default=0.0))

    return None


class OpenAIChat:
    """
    A client for interacting with OpenAI's GPT models with automatic retry logic.

    Supports GPT-5 (Responses API) models
    with exponential backoff retry for transient errors.
    """

    def __init__(self, model: str) -> None:
        """
        Initialize the OpenAI chat client.

        Args:
            model: The OpenAI model to use (e.g., 'gpt-5')

        Raises:
            ValueError: If the API key is not found in environment
        """
        api_key = OPENAI_API_KEY
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment")

        self.client: OpenAI = OpenAI(api_key=api_key)
        self.model = model

        # Import OpenAI exceptions safely
        self._RETRYABLE_ERRORS = _setup_retryable_errors()

    def _params_for_model(self, model: str, **kwargs: Any) -> dict[str, Any]:
        """
        Return default parameters based on model family.

        Args:
            model: The model name (e.g., 'gpt-4.1', 'gpt-5')
            **kwargs: Additional parameters to override defaults

        Returns:
            Dictionary of parameters for the specific model

        Raises:
            ValueError: If the model is not supported
        """
        if model.startswith("gpt-5"):
            # Build GPT-5 parameters with cleaner conditional logic
            parameters = {
                "max_output_tokens": kwargs.get(
                    "max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS_GPT5
                ),
                "text": {"verbosity": kwargs.get("verbosity", DEFAULT_VERBOSITY)},
                "reasoning": {"effort": kwargs.get("reasoning_effort", DEFAULT_REASONING_EFFORT)},
                "tool_choice": kwargs.get("tool_choice", DEFAULT_TOOL_CHOICE),
                "tools": kwargs.get("tools", []),
            }
            return parameters
        else:
            raise ValueError(f"Unsupported model: {model}")

    def generate(self, messages: list[Message], **kwargs: Any) -> dict[str, Any]:
        """
        Generate a response from the OpenAI model with retry logic.

        Args:
            messages: List of Message objects to send to the model
            **kwargs: Additional parameters to pass to the model

        Returns:
            Dictionary containing:
                - content: The generated text response
                - usage: Token usage information
                - parameters: Parameters used for the request
                - model_version: Model version used (GPT-5 only)

        Raises:
            RuntimeError: If the model fails after all retry attempts
            ValueError: If the model is not supported
        """
        # Format messages to OpenAI format
        input_messages = [m.__dict__ for m in messages]

        # Merge defaults with filtered overrides
        request_params = self._params_for_model(model=self.model, **kwargs)

        # Retry with exponential backoff and jitter
        max_attempts = DEFAULT_MAX_ATTEMPTS
        retry_delay = DEFAULT_RETRY_DELAY

        for attempt in range(max_attempts):
            try:
                # ------- Use Responses API for GPT 5 -------
                if self.model.startswith("gpt-5"):
                    return self._handle_gpt5_response(input_messages, request_params)

                else:
                    raise ValueError(f"Unsupported model: {self.model}")

            except self._RETRYABLE_ERRORS as e:  # Transient error occurred -- retry
                if attempt == max_attempts - 1:  # Break after maximum attempts
                    break

                guided = _retry_sleep_seconds_from_headers(e)  # Find sleep time from headers
                if guided is not None:
                    # Add a tiny jitter to avoid thundering herd
                    sleep = guided + random.uniform(0.1, 0.4)
                else:
                    # Fallback to exponential backoff with jitter
                    sleep = min(retry_delay * (0.5**attempt), 30.0) + random.uniform(0, 0.4)

                time.sleep(max(0.0, sleep))

            except Exception as e:  # Non-retryable
                raise RuntimeError(f"Fatal error calling {self.model}: {e}") from e

        raise RuntimeError(f"LLM call failed after {max_attempts} attempts")

    def _handle_gpt5_response(
        self, input_messages: list[dict[str, Any]], request_params: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Handle GPT-5 response using the Responses API.

        Args:
            input_messages: Formatted messages for the API
            request_params: Parameters for the request

        Returns:
            Dictionary with content, usage, parameters, and model_version

        Raises:
            RuntimeError: If the response is empty or invalid
        """
        try:
            resp = self.client.responses.create(
                model=self.model,
                input=cast(Any, input_messages),
                **request_params,
            )
            # resp is already the correct type from the API
        except Exception:
            raise

        # TODO: Add validations for the response

        # Extract reasoning tokens
        u = getattr(resp, "usage", None)
        reasoning_tokens = getattr(
            getattr(u, "output_tokens_details", 0),
            "reasoning_tokens",
            None,
        )

        # Extract usage information
        u = getattr(resp, "usage", None)
        usage = {
            "input_tokens": getattr(u, "input_tokens", 0),
            "output_tokens": getattr(u, "output_tokens", 0),
            "total_tokens": getattr(u, "total_tokens", 0),
            "reasoning_tokens": reasoning_tokens,
        }

        model_version = getattr(resp, "model", None)

        # Extract tool calls
        name = None
        args = None

        output_items = getattr(resp, "output", []) or []

        for item in output_items:
            item_type = getattr(item, "type", "")
            if item_type in ("function_call", "tool_call"):
                name = getattr(item, "name", None)
                args = getattr(item, "arguments", "{}") or "{}"
                break  # Take the first tool call found

        if not name or not isinstance(name, str):
            # Check if there's any text output that might indicate why no tool was called
            text_output = getattr(resp, "output_text", None)
            if text_output:
                raise RuntimeError(f"No tool call found. Model response: {text_output}")
            else:
                raise RuntimeError("Tool call name was not found - no tool calls in response")

        return {
            "usage": usage,
            "parameters": request_params,
            "model_version": model_version,
            "tool_name": name,
            "tool_arguments": args,
        }
