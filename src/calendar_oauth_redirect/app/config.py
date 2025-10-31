from dataclasses import dataclass
from typing import Any

from infrastructure.platform_manager import get_parameters

GOOGLE_TOKEN_TTL = 3600 * 20 * 14  # 14 days


def _validate_params(params: dict[str, Any]) -> list[str]:
    """Validate that all required parameters have a value.
    Args:
        params: The parameters dictionary
    Returns:
        The list of parameters that are missing a value
    """
    missing_params = []
    for param, value in params.items():
        if not value:
            missing_params.append(f"Parameter is required but was empty or None: {param}")
    return missing_params


def _get_parameter_store_config() -> dict[str, Any]:
    """Retrieve and validate all parameters from the parameter store.

    Returns:
        Dictionary containing all configuration parameters

    Raises:
        ValueError: If any required parameters are missing
    """
    # Get required secrets from Parameter Store
    required_secrets = [
        "calendar_token_encryption_key",
        "redis_password",
        "google_client_id",
        "google_client_secret",
    ]
    secrets = get_parameters(
        required_secrets,
        "/apps/prod/calendar/secrets",
        decrypt=True,
    )

    # Get required calendar parameters from Parameter Store
    required_calendar_params = [
        "google_redirect_uri",
        "google_scopes",
        "redis_host",
        "redis_port",
    ]
    calendar_params = get_parameters(
        required_calendar_params,
        "/apps/prod/calendar",
        decrypt=False,
    )

    # Handle google_scopes, which need to be a list but might be stored as a string
    # Use parameter store value or fallback to default
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

    # Validate parameters
    missing_params = _validate_params(secrets)
    if missing_params:
        raise ValueError(f"Missing required parameters: {missing_params}")

    missing_params = _validate_params(calendar_params)
    if missing_params:
        raise ValueError(f"Missing required parameters: {missing_params}")

    # Build redis URL
    redis_password = secrets["redis_password"]
    redis_host = calendar_params["redis_host"]
    redis_port = calendar_params["redis_port"]
    redis_url = f"redis://:{redis_password}@{redis_host}:{redis_port}/0"

    return {
        "calendar_token_encryption_key": secrets["calendar_token_encryption_key"],
        "google_client_id": secrets["google_client_id"],
        "google_client_secret": secrets["google_client_secret"],
        "google_redirect_uri": calendar_params["google_redirect_uri"],
        "google_scopes": google_scopes,
        "redis_url": redis_url,
    }


@dataclass
class Settings:
    """Application settings loaded from parameter store.

    Attributes:
        google_client_id: Google OAuth client ID
        google_client_secret: Google OAuth client secret
        google_redirect_uri: OAuth redirect URI for Google authentication
        google_scopes: List of Google API scopes to request
        redis_url: Redis connection URL
    """

    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str
    google_scopes: list[str]
    redis_url: str
    calendar_token_encryption_key: str


# Load configuration from parameter store
_config = _get_parameter_store_config()
settings = Settings(**_config)
