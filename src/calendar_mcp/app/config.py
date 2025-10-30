from dataclasses import dataclass
from typing import Any

from infrastructure.platform_manager import get_parameters

# Constants
GOOGLE_TOKEN_TTL = 3600 * 20 * 14  # 14 days
HMAC_CLOCK_SKEW = 300  # ±5 minutes in milliseconds


@dataclass
class MCPSettings:
    """MCP configuration settings loaded from parameter store."""

    # Core settings
    agent_hmac_secret: str
    calendar_mcp_url: str
    calendar_token_encryption_key: str

    # Google settings
    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str
    google_scopes: list[str]

    # Redis settings
    redis_url: str


class Config:
    """Singleton configuration manager for the calendar MCP."""

    _instance = None
    _settings = None

    def __new__(cls) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def get_settings(self) -> MCPSettings:
        """Get agent settings, loading from parameter store if not already cached."""
        if self._settings is None:
            self._settings = self._load_settings()
        return self._settings

    def _load_settings(self) -> MCPSettings:
        """Load settings from AWS Parameter Store."""
        # Load secrets (encrypted)
        secrets = get_parameters(
            [
                "agent_hmac_secret",
                "google_client_id",
                "google_client_secret",
                "calendar_token_encryption_key",
                "redis_password",
            ],
            "/apps/prod/calendar/secrets/",
            decrypt=True,
        )

        # Load calendar parameters (not encrypted)
        calendar_params = get_parameters(
            [
                "calendar_mcp_url",
                "google_redirect_uri",
                "google_scopes",
                "redis_host",
                "redis_port",
            ],
            "/apps/prod/calendar/",
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
        assert isinstance(google_scopes, list)
        assert all(isinstance(scope, str) for scope in google_scopes)
        assert len(google_scopes) > 0

        # Build Redis URL
        redis_password = secrets.get('redis_password')
        redis_host = calendar_params.get('redis_host')
        redis_port = calendar_params.get('redis_port')
        assert secrets.get('redis_password') is not None
        assert calendar_params.get('redis_host') is not None
        assert calendar_params.get('redis_port') is not None
        redis_url = f"redis://:{redis_password}@{redis_host}:{redis_port}"

        # Create settings object with proper type assertions
        settings = MCPSettings(
            agent_hmac_secret=secrets.get("agent_hmac_secret") or "",
            calendar_mcp_url=calendar_params.get("calendar_mcp_url") or "",
            calendar_token_encryption_key=secrets.get("calendar_token_encryption_key") or "",
            google_client_id=secrets.get("google_client_id") or "",
            google_client_secret=secrets.get("google_client_secret") or "",
            google_redirect_uri=calendar_params.get("google_redirect_uri") or "",
            google_scopes=google_scopes,
            redis_url=redis_url,
        )

        # Validate settings
        self._validate_settings(settings)

        return settings

    def _validate_settings(self, settings: MCPSettings) -> None:
        """Validate that all required settings have valid values."""
        # Core required fields
        required_fields = [
            "agent_hmac_secret",
            "calendar_mcp_url",
            "calendar_token_encryption_key",
            "google_client_id",
            "google_client_secret",
            "google_redirect_uri",
            "redis_url",
        ]

        # Validate all required fields
        for field in required_fields:
            if not getattr(settings, field):
                raise ValueError(f"Configuration value is invalid: {field.upper()}")

        # Validate google_scopes is not empty
        if not settings.google_scopes:
            raise ValueError("google_scopes must be a non-empty list")


# Create singleton instance
config = Config()


# Convenience functions for backward compatibility
def get_settings() -> MCPSettings:
    """Get agent settings from the singleton config."""
    return config.get_settings()


# Backward compatibility: keep a module-level `settings` object
# so existing imports `from app.config import settings` continue to work.
settings = get_settings()
