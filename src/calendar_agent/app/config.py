from dataclasses import dataclass
from typing import Any

from infrastructure.platform_manager import get_parameters

# Constants that don't change
REDIS_CACHE_PATH = "mcp:cache:calendar:v1"
REDIS_CACHE_TTL = 86400  # 24 hours
X_CLIENT_ID = "dev-test-client-v1"


@dataclass
class AgentSettings:
    """Agent configuration settings loaded from parameter store."""

    # Core settings and certificates
    agent_id: str
    agent_hmac_secret: str
    calendar_mcp_url: str
    calendar_mcp_client_p12: str
    calendar_mcp_client_p12_password: str
    openai_api_key: str

    # Redis settings
    redis_host: str
    redis_port: str
    redis_password: str
    redis_url: str

    # Slack settings
    slack_pa_bot_token: str
    slack_pa_integration: str

    # Optional settings
    calendar_mcp_ca_cert_path: str | None = None
    calendar_mcp_verify_ssl: str | None = None


class Config:
    """Singleton configuration manager for the calendar agent."""

    _instance = None
    _settings = None

    def __new__(cls) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def get_settings(self) -> AgentSettings:
        """Get agent settings, loading from parameter store if not already cached."""
        if self._settings is None:
            self._settings = self._load_settings()
        return self._settings

    def _load_settings(self) -> AgentSettings:
        """Load settings from AWS Parameter Store."""
        # Load secrets (encrypted)
        secrets = get_parameters(
            [
                "agent_hmac_secret",
                "calendar_mcp_client_p12",
                "calendar_mcp_client_p12_password",
                "openai_api_key",
                "redis_password",
                "slack_pa_bot_token",
            ],
            "/apps/prod/calendar/secrets/",
            decrypt=True,
        )

        # Load calendar parameters (not encrypted)
        calendar_params = get_parameters(
            [
                "agent_id",
                "calendar_mcp_url",
                "slack_pa_integration",
                "redis_host",
                "redis_port",
            ],
            "/apps/prod/calendar/",
        )

        # Build Redis URL
        redis_url = f"redis://:{secrets['redis_password']}@{calendar_params['redis_host']}:{calendar_params['redis_port']}"

        # Create settings object with proper type assertions
        settings = AgentSettings(
            agent_id=calendar_params["agent_id"] or "",
            agent_hmac_secret=secrets["agent_hmac_secret"] or "",
            calendar_mcp_url=calendar_params["calendar_mcp_url"] or "",
            calendar_mcp_client_p12=secrets["calendar_mcp_client_p12"] or "",
            calendar_mcp_client_p12_password=secrets["calendar_mcp_client_p12_password"] or "",
            openai_api_key=secrets["openai_api_key"] or "",
            redis_host=calendar_params["redis_host"] or "",
            redis_port=calendar_params["redis_port"] or "",
            redis_password=secrets["redis_password"] or "",
            redis_url=redis_url,
            slack_pa_integration=calendar_params["slack_pa_integration"] or "",
            slack_pa_bot_token=secrets["slack_pa_bot_token"] or "",
        )

        # Validate settings
        self._validate_settings(settings)

        return settings

    def _validate_settings(self, settings: AgentSettings) -> None:
        """Validate that all required settings have valid values."""
        # Core required fields
        required_fields = [
            "agent_id",
            "agent_hmac_secret",
            "calendar_mcp_url",
            "calendar_mcp_client_p12",
            "calendar_mcp_client_p12_password",
            "openai_api_key",
            "redis_host",
            "redis_password",
            "redis_port",
            "redis_url",
        ]

        # Add Slack fields if integration is enabled
        if settings.slack_pa_integration == "true":
            required_fields.extend([
                "slack_pa_bot_token",
                "slack_pa_allowed_users",
                "slack_pa_allowed_channels",
                "slack_pa_allowed_bot",
            ])

        # Validate all required fields
        for field in required_fields:
            if not getattr(settings, field):
                raise ValueError(f"Configuration value is invalid: {field.upper()}")


# Create singleton instance
config = Config()


# Convenience functions
def get_settings() -> AgentSettings:
    """Get agent settings from the singleton config."""
    return config.get_settings()


# Legacy constants for backward compatibility (deprecated - use get_settings() instead)


# Legacy constant accessors (deprecated)
def __getattr__(name: str) -> Any:
    """Provide backward compatibility for legacy constant access."""
    legacy_mapping = {
        "AGENT_ID": "agent_id",
        "AGENT_HMAC_SECRET": "agent_hmac_secret",
        "CALENDAR_MCP_URL": "calendar_mcp_url",
        "CALENDAR_MCP_CLIENT_P12": "calendar_mcp_client_p12",
        "CALENDAR_MCP_CLIENT_P12_PASSWORD": "calendar_mcp_client_p12_password",
        "OPENAI_API_KEY": "openai_api_key",
        "REDIS_HOST": "redis_host",
        "REDIS_PASSWORD": "redis_password",
        "REDIS_PORT": "redis_port",
        "REDIS_URL": "redis_url",
        "SLACK_PA_ALLOWED_BOT": "slack_pa_allowed_bot",
        "SLACK_PA_ALLOWED_CHANNELS": "slack_pa_allowed_channels",
        "SLACK_PA_ALLOWED_USERS": "slack_pa_allowed_users",
        "SLACK_PA_BOT_TOKEN": "slack_pa_bot_token",
        "SLACK_PA_INTEGRATION": "slack_pa_integration",
        "CALENDAR_MCP_CA_CERT_PATH": "calendar_mcp_ca_cert_path",
        "CALENDAR_MCP_VERIFY_SSL": "calendar_mcp_verify_ssl",
    }

    if name in legacy_mapping:
        settings = get_settings()
        return getattr(settings, legacy_mapping[name])

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
