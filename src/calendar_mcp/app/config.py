from dataclasses import dataclass
from typing import Any

from pydantic import field_validator

from infrastructure.platform_manager import get_parameters

GOOGLE_TOKEN_TTL = 3600 * 20 * 14  # 14 days


def _validate_required_param(value: str | None, param_name: str) -> str:
    """Validate that a required parameter is not empty.

    Args:
        value: The parameter value to validate
        param_name: The name of the parameter for error messages

    Returns:
        The validated value

    Raises:
        ValueError: If the parameter is empty or None
    """
    if not value:
        raise ValueError(f"{param_name} is required but was empty or None")
    return value


def _get_param_with_default(params: dict[str, Any] | None, key: str, default: str) -> str:
    """Get a parameter value with a default fallback.

    Args:
        params: The parameters dictionary (may be None)
        key: The parameter key to retrieve
        default: The default value to use if parameter is missing or None

    Returns:
        The parameter value or default if missing/None
    """
    if params is None:
        return default
    value = params.get(key)
    return value if value is not None else default


def _get_parameter_store_config() -> dict[str, Any]:
    """Retrieve and validate all parameters from the parameter store.

    Returns:
        Dictionary containing all configuration parameters

    Raises:
        ValueError: If any required parameters are missing
    """
    # Get secrets
    secrets = get_parameters(
        [
            "calendar_bearer_token",
            "calendar_token_encryption_key",
            "redis_password",
            "google_client_secret",
        ],
        "/apps/prod/calendar/secrets",
        decrypt=True,
    )

    # Get calendar parameters
    calendar_params = get_parameters(
        [
            "calendar_mcp_default_tz",
            "calendar_mcp_url",
            "google_client_id",
            "google_redirect_uri",
            "google_scopes",
            "redis_host",
            "redis_port",
        ],
        "/apps/prod/calendar",
        decrypt=False,
    )

    # Validate and extract secrets
    calendar_bearer_token = _validate_required_param(
        _get_param_with_default(secrets, "calendar_bearer_token", ""), "calendar_bearer_token"
    )
    calendar_token_encryption_key = _validate_required_param(
        _get_param_with_default(secrets, "calendar_token_encryption_key", ""),
        "calendar_token_encryption_key",
    )
    redis_password = _validate_required_param(
        _get_param_with_default(secrets, "redis_password", ""), "redis_password"
    )
    google_client_secret = _validate_required_param(
        _get_param_with_default(secrets, "google_client_secret", ""), "google_client_secret"
    )

    # Validate and extract calendar parameters
    calendar_mcp_default_tz = _get_param_with_default(
        calendar_params, "calendar_mcp_default_tz", "Europe/London"
    )
    calendar_mcp_url = _validate_required_param(
        _get_param_with_default(calendar_params, "calendar_mcp_url", ""), "calendar_mcp_url"
    )
    google_redirect_uri = _validate_required_param(
        _get_param_with_default(calendar_params, "google_redirect_uri", ""), "google_redirect_uri"
    )
    google_client_id = _validate_required_param(
        _get_param_with_default(calendar_params, "google_client_id", ""), "google_client_id"
    )
    redis_host = _validate_required_param(
        _get_param_with_default(calendar_params, "redis_host", ""), "redis_host"
    )
    redis_port = _validate_required_param(
        _get_param_with_default(calendar_params, "redis_port", ""), "redis_port"
    )

    # Handle google_scopes - use parameter store value or fallback to default
    google_scopes_param: Any = calendar_params.get("google_scopes") if calendar_params else None
    if google_scopes_param:
        # If it's a string, split by comma; if it's already a list, use as-is
        if isinstance(google_scopes_param, str):
            google_scopes = [
                scope.strip() for scope in google_scopes_param.split(",") if scope.strip()
            ]
        else:
            # Handle case where it's already a list or other iterable
            google_scopes = list(google_scopes_param)
    else:
        # Fallback to default scopes
        google_scopes = [
            "https://www.googleapis.com/auth/calendar.events",
            "https://www.googleapis.com/auth/calendar.readonly",
        ]

    # Build redis URL
    redis_url = f"redis://:{redis_password}@{redis_host}:{redis_port}/0"

    return {
        "calendar_mcp_url": calendar_mcp_url,
        "default_tz": calendar_mcp_default_tz,
        "google_client_id": google_client_id,
        "google_client_secret": google_client_secret,
        "google_redirect_uri": google_redirect_uri,
        "google_scopes": google_scopes,
        "redis_url": redis_url,
        "calendar_token_encryption_key": calendar_token_encryption_key,
        "calendar_bearer_token": calendar_bearer_token,
    }


@dataclass
class Settings:
    """Application settings loaded from parameter store.

    Attributes:
        calendar_mcp_url: Base URL for the calendar MCP service
        default_tz: Default timezone for calendar operations
        google_client_id: Google OAuth client ID
        google_client_secret: Google OAuth client secret
        google_redirect_uri: OAuth redirect URI for Google authentication
        google_scopes: List of Google API scopes to request
        redis_url: Redis connection URL
        mcp_bearer_token: Bearer token for MCP authentication
    """

    calendar_mcp_url: str
    default_tz: str
    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str
    google_scopes: list[str]
    redis_url: str
    calendar_bearer_token: str
    calendar_token_encryption_key: str

    @field_validator('google_scopes')
    @classmethod
    def validate_google_scopes(cls, v: list[str]) -> list[str]:
        """Validate that google_scopes is a non-empty list.

        Args:
            v: The google_scopes value to validate

        Returns:
            The validated google_scopes list

        Raises:
            ValueError: If google_scopes is empty
        """
        if not v:
            raise ValueError("google_scopes must be a non-empty list")
        return v

    @field_validator('redis_url')
    @classmethod
    def validate_redis_url(cls, v: str) -> str:
        """Validate that redis_url is properly formatted.

        Args:
            v: The redis_url value to validate

        Returns:
            The validated redis_url

        Raises:
            ValueError: If redis_url is not properly formatted
        """
        if not v.startswith('redis://'):
            raise ValueError("redis_url must start with 'redis://'")
        return v


# Load configuration from parameter store
_config = _get_parameter_store_config()
settings = Settings(**_config)
