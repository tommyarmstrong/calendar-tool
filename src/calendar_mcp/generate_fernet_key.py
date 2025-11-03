"""
Fernet Key Generator

This script generates and manages encryption keys for the calendar MCP service.
It checks for existing keys in AWS Parameter Store and generates new ones if needed.
"""

import os

from cryptography.fernet import Fernet
from shared_infrastructure.platform_manager import get_parameters


def generate_fernet_key(key: str, value: str | None) -> None:
    """
    Generate or display a Fernet encryption key.

    Args:
        key: The parameter name for the encryption key
        value: The existing key value (None if no key exists)
    """
    # Generate a new key if none exists (for development)
    print("-" * 10)
    print(key.upper())

    if not value:
        # Generate a new Fernet key and decode it to a string
        value = Fernet.generate_key().decode()

        # Save as environment variable
        os.environ[key.upper()] = value
        print(f"Generated new encryption key for {key}: {value}\n")

        # Provide instructions for setting up the environment variable
        print("Run these commands to set the environment variable:")
        print(f"echo 'export {key.upper()}={value}' >> ~/.zshrc && source ~/.zshrc")
        print(f"printenv|grep {key.upper()}")

        # Provide AWS Parameter Store upload command
        print(
            "python aws_upsert_parameters.py --region us-east-1 --base-path /apps/prod/secrets "
            + f"--env-keys {key.upper()} --encrypt"
        )
        print()

    else:
        # Display the existing key
        print(f"Using existing encryption key {key}: {value[:4]}***********")


# Main execution
print("Evaluating keys in the parameter store")

# Define the required encryption keys for the calendar service
required_keys = ["calendar_token_encryption_key", "calendar_bearer_token"]

# Fetch existing keys from AWS Parameter Store
secrets = get_parameters(required_keys, "/apps/prod/secrets", decrypt=True)

# Process each key - generate new ones if missing
for k, v in secrets.items():
    generate_fernet_key(k, v)

print("\nDone")
