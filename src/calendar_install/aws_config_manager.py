#!/usr/bin/env python3
"""
AWS Configuration Management Script

This script creates a data model for configuring the calendar agent system.
It reads configuration from a JSON file and provides command-line argument overrides.
"""

import argparse
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import boto3


@dataclass
class Layer:
    """AWS Lambda layer configuration."""

    layer_name: str
    layer_type: str = "custom_layer"
    layer_packages: list[str] = field(default_factory=list)


@dataclass
class LambdaDef:
    function_name: str
    handler_name: str
    region_name: str
    runtime: str
    timeout: int
    memory_size: int
    role_name: str
    zip_filename: str
    code_files: list[str]
    layers: list[Layer] = field(default_factory=list)
    architecture: str = "x86_64"  # arm64 or x86_64
    description: str = ""
    environment: dict[str, str] = field(default_factory=dict)
    policy_name: str | None = None


@dataclass
class AWSConfig:
    """Main configuration dataclass for AWS Calendar Agent."""

    function_name: str
    handler_name: str
    region_name: str
    runtime: str
    timeout: int
    memory_size: int
    role_name: str
    zip_filename: str
    code_files: list[str]
    account_id: str
    code_directory: Path
    architecture: str = field(default="x86_64")
    policy_name: str | None = None
    policy_file: str | None = None
    layers: list[Layer] = field(default_factory=list)
    test_event_data: dict[str, Any] = field(default_factory=dict)
    parameters: list[dict[str, str | bool]] = field(default_factory=list)
    api_routes: list[dict[str, str]] = field(default_factory=list)
    apigateway_routes: list[dict[str, str]] = field(default_factory=list)
    invoke_lambda_permissions: list[str] = field(default_factory=list)

    @classmethod
    def _get_env_value(cls, key: str, is_secret: bool = False) -> str | None:
        """
        Get value from environment variable, trying different case variations.

        Args:
            key: The parameter/secret name from JSON
            is_secret: Whether this is a secret (affects logging)

        Returns:
            str | None: The environment variable value or None if not found
        """
        # Extract the base name (last part after /)
        base_name = key.split("/")[-1]

        # Try different case variations
        env_var_names = [
            base_name.upper(),
            base_name.lower(),
            base_name,
        ]

        for env_var_name in env_var_names:
            value = os.getenv(env_var_name)
            if value is not None:
                if is_secret:
                    # For secrets, log name and masked value
                    masked_value = value[:3] + "*********" if len(value) > 3 else "***"
                    logger.debug(
                        f"Using environment variable for secret {base_name}: {masked_value}"
                    )
                else:
                    # For parameters, log name and full value
                    logger.debug(f"Using environment variable for parameter {base_name}: {value}")
                return value

        # If not found in environment, log that we're using JSON value
        if is_secret:
            logger.info(f"Using JSON value for secret {base_name} (environment variable not found)")
        else:
            logger.info(
                f"Using JSON value for parameter {base_name} (environment variable not found)"
            )

        return None

    @classmethod
    def _process_invoke_lambda_permissions(cls, permissions: Any) -> list[str]:
        """
        Process invoke_lambda_permissions from config, handling both string and list cases.

        Args:
            permissions: Either a string, list of strings, or None/empty

        Returns:
            list[str]: List of lambda function names
        """
        if not permissions:
            return []

        if isinstance(permissions, str):
            return [permissions]
        elif isinstance(permissions, list):
            result = []
            for item in permissions:
                if item is not None and isinstance(item, str | int | float):
                    item_str = str(item).strip()
                    if item_str:
                        result.append(item_str)
            return result
        else:
            return []

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AWSConfig":
        """Create AWSConfig from dictionary."""
        # Convert layers list to Layer objects
        layers: list[Layer] = []
        for layer_data in data.get("layers", []):
            layers.append(
                Layer(
                    layer_name=layer_data["layer_name"],
                    layer_type=layer_data.get("layer_type", "custom_layer"),
                    layer_packages=layer_data.get("layer_packages", []),
                )
            )

        # Transform parameters for encryption
        transformed_parameters: list[dict[str, str | bool]] = []

        # Handle parameters (non-encrypted)
        if "parameters" in data and isinstance(data["parameters"], dict):
            for key, value in data["parameters"].items():
                assert isinstance(key, str), f"Key for {key} is not a string"
                # Strip leading slash if present
                clean_key = key.lstrip("/")
                # Try to get value from environment variable first
                env_value = cls._get_env_value(key, is_secret=False)
                final_value = env_value if env_value is not None else value

                transformed_parameters.append({
                    "Name": clean_key.lower(),  # Always use lowercase for AWS
                    "Value": final_value,
                    "Type": "String",
                    "Overwrite": True,
                })

        # Handle secrets (encrypted)
        if "secrets" in data and isinstance(data["secrets"], dict):
            for key, value in data["secrets"].items():
                assert isinstance(key, str), f"Key for {key} is not a string"
                # Strip leading slash if present
                clean_key = key.lstrip("/")
                # Try to get value from environment variable first
                env_value = cls._get_env_value(key, is_secret=True)
                final_value = env_value if env_value is not None else value

                transformed_parameters.append({
                    "Name": clean_key.lower(),  # Always use lowercase for AWS
                    "Value": final_value,
                    "Type": "SecureString",
                    "Overwrite": True,
                    "Tier": "Standard",
                })

        return cls(
            function_name=data["function_name"],
            handler_name=data["handler_name"],
            region_name=data["region_name"],
            runtime=data.get("runtime", "python3.13"),
            architecture=data.get("architecture", "x86_64"),
            timeout=data.get("timeout", 60),
            memory_size=data.get("memory_size", 128),
            role_name=data["role_name"],
            policy_name=data.get("policy_name"),
            policy_file=data.get("policy_file"),
            zip_filename=data["zip_filename"],
            code_files=data["code_files"],
            layers=layers,
            test_event_data=data.get("test_event_data", {}),
            parameters=transformed_parameters,
            account_id=data.get("account_id", ""),
            api_routes=data.get("api_routes", []),
            apigateway_routes=data.get("apigateway_routes", []),
            code_directory=Path(data.get("code_directory", "")),
            invoke_lambda_permissions=cls._process_invoke_lambda_permissions(
                data.get("invoke_lambda_permissions", [])
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert AWSConfig to dictionary."""
        result: dict[str, Any] = {
            "function_name": self.function_name,
            "handler_name": self.handler_name,
            "region_name": self.region_name,
            "runtime": self.runtime,
            "architecture": self.architecture,
            "timeout": self.timeout,
            "memory_size": self.memory_size,
            "role_name": self.role_name,
            "zip_filename": self.zip_filename,
            "code_files": self.code_files,
            "account_id": self.account_id,
            "code_directory": str(self.code_directory),
        }

        # Only include optional fields if they have values
        if self.policy_name is not None:
            result["policy_name"] = self.policy_name
        if self.policy_file is not None:
            result["policy_file"] = self.policy_file
        if self.layers:
            result["layers"] = [
                {
                    "layer_name": layer.layer_name,
                    "layer_type": layer.layer_type,
                    "layer_packages": layer.layer_packages,
                }
                for layer in self.layers
            ]
        if self.test_event_data:
            result["test_event_data"] = self.test_event_data
        if self.parameters:
            result["parameters"] = self.parameters
        if self.api_routes:
            result["api_routes"] = self.api_routes
        if self.apigateway_routes:
            result["apigateway_routes"] = self.apigateway_routes
        if self.invoke_lambda_permissions:
            result["invoke_lambda_permissions"] = self.invoke_lambda_permissions

        return result


def get_aws_account_id(region_name: str = "us-east-1") -> str:
    """
    Get the AWS account ID using STS.

    Args:
        region_name: AWS region name

    Returns:
        str: AWS account ID

    Raises:
        Exception: If unable to get account ID
    """
    try:
        sts = boto3.client("sts", region_name=region_name)
        response = sts.get_caller_identity()
        return str(response["Account"])
    except Exception as e:
        raise Exception(f"Failed to get AWS account ID: {e}") from e


def get_config(config_file: str) -> AWSConfig:
    """
    Load configuration from JSON file and return AWSConfig object.

    Args:
        config_file: Path to the JSON configuration file

    Returns:
        AWSConfig: Configuration object

    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is not valid JSON
        KeyError: If required fields are missing from config
    """
    config_path = Path(config_file)

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_file}")

    with open(config_path) as f:
        data = json.load(f)

    # Get AWS account ID and add it to the config
    try:
        account_id = get_aws_account_id(data.get("region_name", "us-east-1"))
        data["account_id"] = account_id
    except Exception as e:
        print(f"Warning: Could not get AWS account ID: {e}")
        data["account_id"] = ""

    # Get the full path to the config directory

    if data.get("code_directory"):
        code_directory = Path(data.get("code_directory"))
    else:
        code_directory = Path(config_path.parent)
    data["code_directory"] = code_directory

    return AWSConfig.from_dict(data)


def create_logger(
    log_level: str = "INFO",
    logger_name: str = "calendar-agent",
    logs_dir: str | Path = "logs",
) -> logging.Logger:
    """
    Create a logger that outputs to console and optionally to a file.

    Args:
        log_level (str): Logging level (e.g., "INFO", "DEBUG").
        logger_name (str): Name for the logger instance.
        logs_dir (str | Path | None): Directory for log files. If None, uses default based on
            environment.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logs_dir = Path(logs_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, log_level.upper(), logging.DEBUG))
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    if not logger.hasHandlers():  # Prevent handler duplication
        # Console handler (stdio) - always add this
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        try:
            file_handler = logging.FileHandler(logs_dir / logger_name)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception:
            # If file logging fails, just continue with console logging
            pass

    return logger


# Create logger after create_logger function is defined
logger = create_logger(logger_name="aws_config", log_level="INFO")


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments for configuration overrides.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="AWS Calendar Agent Configuration Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Configuration file
    parser.add_argument(
        "--config-file",
        "-c",
        default="aws_config.json",
        help="Path to JSON configuration file (default: aws_config.json)",
    )

    return parser.parse_args()


def print_config(config: AWSConfig) -> None:
    """
    Print configuration in a readable format.

    Args:
        config: Configuration to print
    """
    print("=" * 60)
    print("AWS Calendar Agent Configuration")
    print("=" * 60)

    print("\n📦 Lambda Function:")
    print(f"  Function Name: {config.function_name}")
    print(f"  Handler: {config.handler_name}")
    print(f"  Region: {config.region_name}")
    print(f"  Runtime: {config.runtime}")
    print(f"  Timeout: {config.timeout}s")
    print(f"  Memory: {config.memory_size}MB")
    print(f"  Account ID: {config.account_id}")

    print("\n🔐 IAM Configuration:")
    print(f"  Role Name: {config.role_name}")
    if config.policy_name:
        print(f"  Policy Name: {config.policy_name}")
        print(f"  Policy File: {config.policy_file}")
    else:
        print("  Policy: (no custom policy configured)")

    print("\n📁 Deployment:")
    print(f"  Zip Filename: {config.zip_filename}")
    print(f"  Code Files: {len(config.code_files)} files")

    print("\n🔧 Layers:")
    if config.layers:
        for i, layer in enumerate(config.layers, 1):
            print(f"  {i}. {layer.layer_name} ({layer.layer_type})")
            print(f"     Packages: {', '.join(layer.layer_packages)}")
    else:
        print("  (no layers configured)")

    print("\n⚙️  Parameters:")
    if config.parameters:
        for param_info in config.parameters:
            key = param_info["Name"]
            if isinstance(key, str):
                key = key.split("/")[-1].upper()
            if param_info["Type"] == "SecureString":
                value = "*" * 8
            else:
                value = str(param_info["Value"])
            print(f"  {key}:")
            print(f"    Name: {param_info['Name']}")
            print(f"    Value: {value}")
            print(f"    Type: {param_info['Type']}")
            print(f"    Overwrite: {param_info['Overwrite']}")
    else:
        print("  (no parameters configured)")

    print("\n📊 Test Event Data:")
    if config.test_event_data:
        print(f"  {config.test_event_data}")
    else:
        print("  (empty)")

    print("\n🌐 API Gateway Routes:")
    if config.apigateway_routes:
        for i, route in enumerate(config.apigateway_routes, 1):
            print(f"  {i}. {route.get('method', 'N/A')} {route.get('path', 'N/A')}")
            print(f"     Lambda: {route.get('lambda', 'N/A')}")
            if route.get("stage"):
                print(f"     Stage: {route.get('stage')}")
    else:
        print("  (no API Gateway routes configured)")

    print("\n" + "=" * 60)


def main() -> int:
    """Main function to run the configuration manager."""
    try:
        # Parse command line arguments
        args = parse_args()

        # Load configuration from file
        config = get_config(args.config_file)

        # Print the final configuration
        print_config(config)

    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        return 1
    except json.JSONDecodeError as e:
        print(f"❌ JSON Error: {e}")
        return 1
    except KeyError as e:
        print(f"❌ Configuration Error: Missing required field {e}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
