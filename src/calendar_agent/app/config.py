from infrastructure.platform_manager import get_parameters

REDIS_CACHE_PATH = "mcp:cache:calendar:v1"
REDIS_CACHE_TTL = 86400  # 24 hours

X_CLIENT_ID = "dev-test-client-v1"

# Secrets are encrypted in the AWS Parameter Store
secrets = get_parameters(
    [
        "calendar_bearer_token",
        "calendar_mcp_client_p12",
        "calendar_mcp_client_p12_password",
        "openai_api_key",
        "redis_password",
        "slack_pa_bot_token",
    ],
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
        "calendar_mcp_ca_cert_b64",
        "calendar_mcp_url",
        "slack_pa_integration",
        "slack_pa_allowed_users",
        "slack_pa_allowed_channels",
        "slack_pa_allowed_bot",
    ],
    "/apps/prod/calendar/",
)

CALENDAR_BEARER_TOKEN = secrets["calendar_bearer_token"]
CALENDAR_MCP_CLIENT_P12 = secrets["calendar_mcp_client_p12"]
CALENDAR_MCP_CLIENT_P12_PASSWORD = secrets["calendar_mcp_client_p12_password"]
OPENAI_API_KEY = secrets["openai_api_key"]
REDIS_PASSWORD = secrets["redis_password"]

CALENDAR_MCP_CA_CERT_B64 = calendar_params["calendar_mcp_ca_cert_b64"]
CALENDAR_MCP_URL = calendar_params["calendar_mcp_url"]
REDIS_HOST = infra_params["redis_host"]
REDIS_PORT = infra_params["redis_port"]
REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}"
SLACK_PA_ALLOWED_BOT = calendar_params["slack_pa_allowed_bot"]
SLACK_PA_ALLOWED_CHANNELS = calendar_params["slack_pa_allowed_channels"]
SLACK_PA_ALLOWED_USERS = calendar_params["slack_pa_allowed_users"]
SLACK_PA_BOT_TOKEN = secrets["slack_pa_bot_token"]
SLACK_PA_INTEGRATION = calendar_params["slack_pa_integration"]

CALENDAR_MCP_CA_CERT_PATH = None
CALENDAR_MCP_VERIFY_SSL = None

# Validate configuration values
for key, value in {
    "CALENDAR_BEARER_TOKEN": CALENDAR_BEARER_TOKEN,
    "CALENDAR_MCP_CA_CERT_B64": CALENDAR_MCP_CA_CERT_B64,
    "CALENDAR_MCP_URL": CALENDAR_MCP_URL,
    "CALENDAR_MCP_CLIENT_P12": CALENDAR_MCP_CLIENT_P12,
    "CALENDAR_MCP_CLIENT_P12_PASSWORD": CALENDAR_MCP_CLIENT_P12_PASSWORD,
    "OPENAI_API_KEY": OPENAI_API_KEY,
    "REDIS_HOST": REDIS_HOST,
    "REDIS_PASSWORD": REDIS_PASSWORD,
    "REDIS_PORT": REDIS_PORT,
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
