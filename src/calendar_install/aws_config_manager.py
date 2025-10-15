#!/usr/bin/env python3
"""
AWS Configuration Management Script

This script creates a data model for configuring the calendar agent system.
It reads configuration from a JSON file and provides command-line argument overrides.
"""

import argparse
import json
import logging
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
    policy_name: str
    policy_file: str
    zip_filename: str
    code_files: list[str]
    layers: list[Layer]
    test_event_data: dict[str, Any]
    parameters: list[dict[str, str | bool]]
    account_id: str
    api_routes: list[dict[str, str]]
    architecture: str = field(default="x86_64")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AWSConfig":
        """Create AWSConfig from dictionary."""
        # Convert layers list to Layer objects
        layers: list[Layer] = []
        for layer_data in data.get("layers", []):
            layers.append(
                Layer(
                    layer_name=layer_data["layer_name"],
                    layer_type=layer_data["layer_type"],
                    layer_packages=layer_data["layer_packages"],
                )
            )

        # Transform parameters for encryption
        transformed_parameters: list[dict[str, str | bool]] = []

        # Handle parameters (non-encrypted)
        if "parameters" in data and isinstance(data["parameters"], dict):
            for key, value in data["parameters"].items():
                transformed_parameters.append({
                    "Name": key,
                    "Value": value,
                    "Type": "String",
                    "Overwrite": True,
                })

        # Handle secrets (encrypted)
        if "secrets" in data and isinstance(data["secrets"], dict):
            for key, value in data["secrets"].items():
                transformed_parameters.append({
                    "Name": key,
                    "Value": value,
                    "Type": "SecureString",
                    "Overwrite": True,
                    "Tier": "Standard",
                })

        return cls(
            function_name=data["function_name"],
            handler_name=data["handler_name"],
            region_name=data["region_name"],
            runtime=data["runtime"],
            architecture=data["architecture"],
            timeout=data["timeout"],
            memory_size=data["memory_size"],
            role_name=data["role_name"],
            policy_name=data["policy_name"],
            policy_file=data["policy_file"],
            zip_filename=data["zip_filename"],
            code_files=data["code_files"],
            layers=layers,
            test_event_data=data["test_event_data"],
            parameters=transformed_parameters,
            account_id=data.get("account_id", ""),
            api_routes=data.get("api_routes", []),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert AWSConfig to dictionary."""
        return {
            "function_name": self.function_name,
            "handler_name": self.handler_name,
            "region_name": self.region_name,
            "runtime": self.runtime,
            "architecture": self.architecture,
            "timeout": self.timeout,
            "memory_size": self.memory_size,
            "role_name": self.role_name,
            "policy_name": self.policy_name,
            "policy_file": self.policy_file,
            "zip_filename": self.zip_filename,
            "code_files": self.code_files,
            "layers": [
                {
                    "layer_name": layer.layer_name,
                    "layer_type": layer.layer_type,
                    "layer_packages": layer.layer_packages,
                }
                for layer in self.layers
            ],
            "test_event_data": self.test_event_data,
            "parameters": self.parameters,
            "account_id": self.account_id,
        }


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
        raise Exception(f"Failed to get AWS account ID: {e}")


def get_config(config_file: str = "aws_agent_config.json") -> AWSConfig:
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

    with open(config_path, "r") as f:
        data = json.load(f)

    # Get AWS account ID and add it to the config
    try:
        account_id = get_aws_account_id(data.get("region_name", "us-east-1"))
        data["account_id"] = account_id
    except Exception as e:
        print(f"Warning: Could not get AWS account ID: {e}")
        data["account_id"] = ""

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
    print(f"  Policy Name: {config.policy_name}")
    print(f"  Policy File: {config.policy_file}")

    print("\n📁 Deployment:")
    print(f"  Zip Filename: {config.zip_filename}")
    print(f"  Code Files: {len(config.code_files)} files")

    print("\n🔧 Layers:")
    for i, layer in enumerate(config.layers, 1):
        print(f"  {i}. {layer.layer_name} ({layer.layer_type})")
        print(f"     Packages: {', '.join(layer.layer_packages)}")

    print("\n⚙️  Parameters:")
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

    print("\n📊 Test Event Data:")
    if config.test_event_data:
        print(f"  {config.test_event_data}")
    else:
        print("  (empty)")

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
