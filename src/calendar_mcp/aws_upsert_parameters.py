#!/usr/bin/env python3
"""
Provision multiple SSM Parameter Store parameters from environment variables.

Examples:
  export OPENAI_API_KEY="sk-..." REDIS_PASSWORD="..." PINECONE_API_KEY="..."
  python3 ssm_setup_secrets.py \
    --region us-east-1 \
    --base-path /apps/prod/secrets \
    --env-keys OPENAI_API_KEY,REDIS_PASSWORD,PINECONE_API_KEY \
    --encrypt   # store as SecureString; omit to store plaintext String

Notes:
  - --encrypt uses AWS-managed KMS key (alias/aws/ssm) implicitly (no KeyId needed).
  - Standard tier (<= 4KB per param) is fine for API keys/passwords.
  - Storing secrets as plaintext is not recommended; prefer --encrypt for sensitive values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from infrastructure.platform_manager import create_logger

DEFAULT_BASE_PATH = "/apps/prod/secrets"


def mask(s: str, show: int = 4) -> str:
    if not s:
        return ""
    return ("*" * max(0, len(s) - show)) + s[-show:]


def to_param_name(env_key: str) -> str:
    """
    Convert ENV_VAR_NAME -> env_var_name (safe SSM leaf name).
    """
    name = env_key.strip().lower()
    name = re.sub(r"[^a-z0-9]+", "_", name).strip("_")
    return name or env_key.lower()


def put_param(
    ssm: Any,
    name: str,
    value: str,
    *,
    encrypt: bool,
    overwrite: bool = True,
    description: str | None = None,
) -> None:
    kwargs = {
        "Name": name,
        "Value": value,
        "Type": "SecureString" if encrypt else "String",
        "Overwrite": overwrite,
        "Tier": "Standard",
    }
    if description:
        kwargs["Description"] = description
    # For SecureString we rely on alias/aws/ssm by not providing KeyId.
    ssm.put_parameter(**kwargs)


def get_parameter(ssm: Any, name: str, *, decrypt: bool) -> str:
    resp = ssm.get_parameter(Name=name, WithDecryption=decrypt)
    return str(resp["Parameter"]["Value"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Push multiple parameters into SSM Parameter Store."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument(
        "--base-path",
        default=DEFAULT_BASE_PATH,
        help=f"Base SSM path (default: {DEFAULT_BASE_PATH})",
    )
    parser.add_argument(
        "--env-keys",
        nargs="+",
        required=True,
        help="Environment variable names to push (e.g. OPENAI_API_KEY REDIS_PASSWORD)",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Store as SecureString (KMS). Omit to store as plaintext String. Default: plaintext.",
    )
    parser.add_argument(
        "--no-overwrite",
        action="store_true",
        help="Fail if the parameter already exists (default: overwrite).",
    )
    parser.add_argument(
        "--description-prefix",
        default="Application parameter: ",
        help='Optional description prefix (default: "Application parameter: ")',
    )
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="If set, exit non-zero if any env var is missing (default: skip missing).",
    )
    parser.add_argument(
        "--json-file",
        help="JSON file with parameter paths and values (format: {\"path/name\": \"value\"})",
    )
    args = parser.parse_args()

    logger = create_logger(log_level="INFO", logger_name="config_parameter_store")

    region = args.region
    base_path = args.base_path.rstrip("/")
    overwrite = not args.no_overwrite
    encrypt = args.encrypt
    env_keys = args.env_keys

    if not env_keys and not args.json_file:
        logger.error("No --env-keys or --json-file provided.")
        return 2

    ssm = boto3.client("ssm", region_name=region)

    wrote, skipped_missing, mismatched = 0, 0, 0
    missing_keys: list[str] = []

    try:
        # Process JSON file if provided
        if args.json_file:
            with open(args.json_file) as f:
                json_params = json.load(f)

            for param_path, value in json_params.items():
                if not value:
                    skipped_missing += 1
                    missing_keys.append(param_path)
                    logger.warning(f"Skipping {param_path}: empty value.")
                    continue

                logger.info(
                    f"Writing {('SecureString' if encrypt else 'String')} "
                    + f"to SSM: {param_path} (region: {region})"
                )
                put_param(
                    ssm=ssm,
                    name=param_path,
                    value=str(value),
                    encrypt=encrypt,
                    overwrite=overwrite,
                    description=f"{args.description_prefix}{param_path}",
                )

                # Brief read-after-write delay
                time.sleep(0.2)

                # Verify without exposing full secret
                fetched = get_parameter(ssm, param_path, decrypt=encrypt)
                ok = fetched == str(value)
                logger.info(
                    f"Verify read: {param_path} = {mask(fetched)} "
                    + f"(match: {'OK' if ok else 'MISMATCH'})"
                )
                if not ok:
                    mismatched += 1
                else:
                    wrote += 1

        # Process environment variables if provided
        if env_keys:
            for env_key in env_keys:
                value = os.getenv(env_key)
                leaf = to_param_name(env_key)
                param_path = f"{base_path}/{leaf}"

                if not value:
                    skipped_missing += 1
                    missing_keys.append(env_key)
                    logger.warning(f"Skipping {env_key}: not set in environment.")
                    continue

                logger.info(
                    f"Writing {('SecureString' if encrypt else 'String')} "
                    + f"to SSM: {param_path} (region: {region})"
                )
                put_param(
                    ssm=ssm,
                    name=param_path,
                    value=value,
                    encrypt=encrypt,
                    overwrite=overwrite,
                    description=f"{args.description_prefix}{env_key}",
                )

                # Brief read-after-write delay
                time.sleep(0.2)

                # Verify without exposing full secret
                fetched = get_parameter(ssm, param_path, decrypt=encrypt)
                ok = fetched == value
                logger.info(
                    f"Verify read: {param_path} = {mask(fetched)} "
                    + f"(match: {'OK' if ok else 'MISMATCH'})"
                )
                if not ok:
                    mismatched += 1
                else:
                    wrote += 1

        if args.require_all and missing_keys:
            logger.error(f"--require-all set and missing env keys: {', '.join(missing_keys)}")
            return 4

        if mismatched > 0:
            logger.error(f"{mismatched} parameter(s) failed verification.")
            return 3

        logger.info(f"Done. Wrote {wrote}, skipped {skipped_missing} missing.")
        storage_type = "SecureString (KMS alias/aws/ssm)" if encrypt else "String (plaintext)"
        logger.info(f"Parameters stored as {storage_type}.")
        logger.info(
            "Lambda/ECS roles need ssm:GetParameter(s) and (if encrypted) kms:Decrypt to read them."
        )
        return 0

    except ClientError as e:
        logger.error(f"AWS error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
