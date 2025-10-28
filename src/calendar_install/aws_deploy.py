import argparse
import sys

from aws_api_gateway_manager import APIGatewayManager
from aws_config_manager import create_logger, get_config
from aws_iam_manager import IAMManager
from aws_lambda_manager import LambdaManager
from aws_parameter_manager import ParameterManager


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments for AWS deployment.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="AWS Calendar Agent Deployment Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--config-file",
        "-c",
        required=True,
        help="Path to JSON configuration file",
    )

    parser.add_argument(
        "--log-level",
        "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level (default: INFO)",
    )

    return parser.parse_args()


def main() -> int:
    """
    Main function to run the AWS deployment from command line.

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        # Parse command line arguments
        args = parse_args()

        # Create logger with specified log level
        logger = create_logger(logger_name="aws_deployment", log_level=args.log_level)
        logger.info("Starting AWS deployment")

        # Read the configuration
        config = get_config(args.config_file)
        logger.info(
            f"Using AWS account ID {config.account_id} and region {config.region_name}"
        )

        # Process and upload parameters to AWS Parameter Store
        logger.info("Deploying parameters")
        parameter_manager = ParameterManager(config.parameters)
        parameter_manager.deploy()

        # Deploy the IAM policy and lambda role
        logger.info("Deploying IAM policy and lambda role")
        iam_manager = IAMManager(
            role_name=config.role_name,
            account_id=config.account_id,
            config=config,
            policy_name=getattr(config, "policy_name", None),
            policy_file=getattr(config, "policy_file", None),
            config_file_path=args.config_file,
        )
        iam_manager.deploy()

        # Deploy the Lambda function
        logger.info("Deploying Lambda function")
        lambda_manager = LambdaManager(config=config)
        lambda_manager.deploy()

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
        return 0

    except FileNotFoundError as e:
        print(f"❌ Error: Configuration file not found: {e}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
