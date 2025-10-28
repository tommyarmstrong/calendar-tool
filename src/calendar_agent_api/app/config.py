import uuid

from infrastructure.platform_manager import get_parameters

secrets = get_parameters(
    ["calendar_bearer_token", "slack_pa_signing_secret", "redis_password"],
    "/apps/prod/calendar/secrets/",
    decrypt=True,
)

CALENDAR_BEARER_TOKEN = secrets["calendar_bearer_token"]
SLACK_PA_SIGNING_SECRET = secrets["slack_pa_signing_secret"]
REDIS_PASSWORD = secrets["redis_password"]

parameters = get_parameters(["redis_host", "redis_port"], "/apps/prod/calendar/")

REDIS_HOST = parameters["redis_host"]
REDIS_PORT = parameters["redis_port"]

INVOKE_LAMBDA_NAME = "calendar_agent"
INVOKE_LAMBDA_FILE = "agent_handler.py"

X_CLIENT_ID = "dev-test-client-v1"

# Validate configuration values
for k, v in {
    "CALENDAR_BEARER_TOKEN": CALENDAR_BEARER_TOKEN,
    "INVOKE_LAMBDA_NAME": INVOKE_LAMBDA_NAME,
    "INVOKE_LAMBDA_FILE": INVOKE_LAMBDA_FILE,
    "REDIS_HOST": REDIS_HOST,
    "REDIS_PORT": REDIS_PORT,
    "REDIS_PASSWORD": REDIS_PASSWORD,
    "SLACK_PA_SIGNING_SECRET": SLACK_PA_SIGNING_SECRET,
    "X_CLIENT_ID": X_CLIENT_ID,
}.items():
    if not v:
        raise ValueError(f"Configuration value is invalid: {k}")


def generate_request_id() -> str:
    return str(uuid.uuid4())
