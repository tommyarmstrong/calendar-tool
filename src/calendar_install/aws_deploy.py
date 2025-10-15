from aws_config_manager import create_logger, get_config
from aws_api_gateway_manager import APIGatewayManager
from aws_iam_manager import IAMManager
from aws_lambda_manager import LambdaManager
from aws_parameter_manager import ParameterManager

logger = create_logger(logger_name="aws_deployment", log_level="INFO")
logger.info("Starting AWS deployment")

# Read the configuration
config = get_config("aws_agent_config.json")
logger.info(f"Using AWS account ID {config.account_id} and region {config.region_name}")

# Process and upload parameters to AWS Parameter Store
logger.info("Deploying parameters")
parameter_manager = ParameterManager(config.parameters, upsert_to_aws=False)
parameter_manager.deploy()


# Deploy the IAM policy and lambda role
logger.info("Deploying IAM policy and lambda role")
iam_manager = IAMManager(
    role_name=config.role_name,
    policy_name=config.policy_name,
    policy_file=config.policy_file,
    account_id=config.account_id,
)
iam_manager.deploy()


# Deploy the Lambda function
logger.info("Deploying Lambda function")
lambda_manager = LambdaManager(config=config)
lambda_manager.deploy


# Deploy the API Routes, if they are defined
if config.api_routes:
    logger.info("Deploying API Routes")
    api_gateway_manager = APIGatewayManager(
        api_name=f"{config.function_name}_api",
        api_routes=config.api_routes,
        account_id=config.account_id,
        region_name=config.region_name,
    )
    api_gateway_manager.deploy()

logger.info("AWS deployment completed")
