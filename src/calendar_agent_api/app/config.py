import uuid
from dataclasses import dataclass

from infrastructure.platform_manager import get_parameters

# Constants that don't change
INVOKE_LAMBDA_NAME = "calendar_agent"
INVOKE_LAMBDA_FILE = "agent_handler.py"  # <-- Unused in AWS deployment; required for FastAPI

X_CLIENT_ID = "dev-test-client-v1"


def generate_request_id() -> str:
    """Generate a unique request ID."""
    return str(uuid.uuid4())


@dataclass
class AgentAPISettings:
    """Agent configuration settings loaded from parameter store."""

    # Core settings and certificates
    calendar_bearer_token: str

    # Redis settings
    redis_host: str
    redis_port: str
    redis_password: str
    redis_url: str

    # Slack settings
    slack_pa_allowed_bot: str
    slack_pa_allowed_channels: str
    slack_pa_allowed_users: str
    slack_pa_integration: str
    slack_pa_signing_secret: str


class Config:
    """Singleton configuration manager for the calendar agent."""

    _instance = None
    _settings = None

    def __new__(cls) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def get_settings(self) -> AgentAPISettings:
        """Get agent settings, loading from parameter store if not already cached."""
        if self._settings is None:
            self._settings = self._load_settings()
        return self._settings

    def _load_settings(self) -> AgentAPISettings:
        """Load settings from AWS Parameter Store."""

        # Load secrets (encrypted)
        secrets = get_parameters(
            ["calendar_bearer_token", "slack_pa_signing_secret", "redis_password"],
            "/apps/prod/calendar/secrets/",
            decrypt=True,
        )

        # Load calendar parameters (not encrypted)
        parameters = get_parameters(
            [
                "redis_host",
                "redis_port",
                "slack_pa_allowed_bot",
                "slack_pa_allowed_channels",
                "slack_pa_allowed_users",
                "slack_pa_integration",
            ],
            "/apps/prod/calendar/",
        )

        # Build Redis URL
        redis_url = f"redis://:{secrets['redis_password']}@{parameters['redis_host']}:{parameters['redis_port']}"

        # Create settings object with proper type assertions
        settings = AgentAPISettings(
            calendar_bearer_token=secrets["calendar_bearer_token"] or "",
            redis_host=parameters["redis_host"] or "",
            redis_port=parameters["redis_port"] or "",
            redis_password=secrets["redis_password"] or "",
            redis_url=redis_url,
            slack_pa_allowed_bot=parameters["slack_pa_allowed_bot"] or "",
            slack_pa_allowed_channels=parameters["slack_pa_allowed_channels"] or "",
            slack_pa_allowed_users=parameters["slack_pa_allowed_users"] or "",
            slack_pa_integration=parameters["slack_pa_integration"] or "",
            slack_pa_signing_secret=secrets["slack_pa_signing_secret"] or "",
        )

        # Validate settings
        self._validate_settings(settings)

        return settings

    def _validate_settings(self, settings: AgentAPISettings) -> None:
        """Validate that all required settings have valid values."""
        # Core required fields
        required_fields = [
            "calendar_bearer_token",
            "redis_host",
            "redis_password",
            "redis_port",
            "redis_url",
        ]

        # Add Slack fields if integration is enabled
        if settings.slack_pa_integration == "true":
            required_fields.extend([
                "slack_pa_allowed_users",
                "slack_pa_allowed_channels",
                "slack_pa_allowed_bot",
                "slack_pa_signing_secret",
            ])

        # Validate all required fields
        for field in required_fields:
            if not getattr(settings, field):
                raise ValueError(f"Configuration value is invalid: {field.upper()}")


# Create singleton instance
config = Config()


# Convenience functions
def get_settings() -> AgentAPISettings:
    """Get agent API settings from the singleton config."""
    return config.get_settings()
