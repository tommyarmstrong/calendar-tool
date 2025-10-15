from infrastructure.platform_manager import get_parameters

REDIS_CACHE_PATH = "mcp:cache:calendar:v1"
REDIS_CACHE_TTL = 86400  # 24 hours

X_CLIENT_ID = "dev-test-client-v1"

# Secrets are encrypted in the AWS Parameter Store
secrets = get_parameters(
    ["openai_api_key", "calendar_bearer_token", "redis_password", "slack_pa_bot_token"],
    "/apps/prod/secrets/",
    decrypt=True,
)

# Infrastructure parameters are not encrypted in the AWS Parameter Store
infra_params = get_parameters(
    ["redis_host", "redis_port"],
    "/apps/prod/infra/",
)

# Config parameters are not encrypted in the AWS Parameter Store
calendar_params = get_parameters(
    [
        "slack_pa_integration",
        "slack_pa_allowed_users",
        "slack_pa_allowed_channels",
        "slack_pa_allowed_bot",
        "calendar_mcp_url",
    ],
    "/apps/prod/calendar/",
)

OPENAI_API_KEY = secrets["openai_api_key"]
CALENDAR_BEARER_TOKEN = secrets["calendar_bearer_token"]
REDIS_PASSWORD = secrets["redis_password"]
SLACK_PA_INTEGRATION = calendar_params["slack_pa_integration"]
SLACK_PA_BOT_TOKEN = secrets["slack_pa_bot_token"]
SLACK_PA_ALLOWED_USERS = calendar_params["slack_pa_allowed_users"]
SLACK_PA_ALLOWED_CHANNELS = calendar_params["slack_pa_allowed_channels"]
SLACK_PA_ALLOWED_BOT = calendar_params["slack_pa_allowed_bot"]
CALENDAR_MCP_URL = calendar_params["calendar_mcp_url"]
REDIS_HOST = infra_params["redis_host"]
REDIS_PORT = infra_params["redis_port"]
REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}"

# Validate configuration values
for key, value in {
    "OPENAI_API_KEY": OPENAI_API_KEY,
    "CALENDAR_BEARER_TOKEN": CALENDAR_BEARER_TOKEN,
    "CALENDAR_MCP_URL": CALENDAR_MCP_URL,
    "REDIS_HOST": REDIS_HOST,
    "REDIS_PORT": REDIS_PORT,
    "REDIS_PASSWORD": REDIS_PASSWORD,
    "REDIS_URL": REDIS_URL,
}.items():
    if not isinstance(value, str) or not value:
        raise ValueError(f"Configuration value is invalid: {key}")

# Validate Slack PA integration configuration
if SLACK_PA_INTEGRATION == "true":
    for key, value in {
        "SLACK_PA_BOT_TOKEN": SLACK_PA_BOT_TOKEN,
        "SLACK_PA_ALLOWED_USERS": SLACK_PA_ALLOWED_USERS,
        "SLACK_PA_ALLOWED_CHANNELS": SLACK_PA_ALLOWED_CHANNELS,
        "SLACK_PA_ALLOWED_BOT": SLACK_PA_ALLOWED_BOT,
    }.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f"Configuration value is invalid: {key}")
