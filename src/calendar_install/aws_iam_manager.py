import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import boto3
from aws_config_manager import create_logger, get_config
from botocore.exceptions import ClientError

logger = create_logger(logger_name="aws_deployment", log_level="INFO")


def retry_with_backoff(
    func: Callable[..., Any],
    *args: Any,
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_multiplier: float = 2.0,
    **kwargs: Any,
) -> Any:
    """
    Retry a function with exponential backoff.

    Args:
        func: Function to retry
        *args: Positional arguments for the function
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        backoff_multiplier: Multiplier for exponential backoff
        **kwargs: Keyword arguments for the function

    Returns:
        The result of the function call

    Raises:
        The last exception if all retries are exhausted
    """
    last_exception: Exception | None = None
    delay = base_delay

    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt == max_retries:
                break

            logger.info(f"Attempt {attempt + 1} failed: {e}")
            logger.info(f"Retrying in {delay:.1f} seconds...")
            time.sleep(delay)
            delay = min(delay * backoff_multiplier, max_delay)

    if last_exception is not None:
        raise last_exception
    raise RuntimeError("Retry logic failed without exception")


class IAMManager:
    def __init__(
        self,
        role_name: str,
        account_id: str,
        config: Any | None = None,
        policy_name: str | None = None,
        policy_file: str | None = None,
        config_file_path: str | None = None,
    ):
        # Validate policy configuration - both must be present or both must be absent
        if (policy_name is None) != (policy_file is None):
            raise ValueError(
                "Both policy_name and policy_file must be provided together, or both must be None"
            )

        self.policy_name = policy_name
        self.policy_file = policy_file
        self.role_name = role_name
        self.account_id = account_id
        self.config_file_path = config_file_path
        self.config = config
        self.policy_arn: str | None = None
        self.auto_policy_arn: str | None = None
        self.has_custom_policy = policy_name is not None and policy_file is not None
        self.has_auto_policy = config is not None and (
            hasattr(config, "parameters") and config.parameters
        )

        self.iam = boto3.client("iam")

    def _generate_auto_policy(self) -> str:
        """
        Generate IAM policy document from parameters and secrets in config.

        Returns:
            str: JSON policy document
        """
        if not self.has_auto_policy or self.config is None:
            raise ValueError("No auto policy configuration available")

        statements = []

        # Handle all parameters (both regular and secrets) in a single statement
        has_secrets = False
        if hasattr(self.config, "parameters") and self.config.parameters:
            parameter_paths = []

            for param in self.config.parameters:
                if isinstance(param, dict) and "Name" in param:
                    name = param["Name"]
                    if isinstance(name, str):
                        parameter_paths.append(name)
                        # Check if this is a secret
                        if param.get("Type") == "SecureString":
                            has_secrets = True

            if parameter_paths:
                statements.append({
                    "Sid": "AllowReadParamsUnderPath",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                        "ssm:DescribeParameters",
                    ],
                    "Resource": [
                        f"arn:aws:ssm:{self.config.region_name}:{self.account_id}:{path}"
                        for path in parameter_paths
                    ],
                })

        # Add KMS decrypt permission if there are secrets
        if has_secrets:
            statements.append({
                "Sid": "AllowDecryptForSecureString",
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "*",
            })

        # If no statements were generated, return empty policy
        if not statements:
            return json.dumps({"Version": "2012-10-17", "Statement": []})

        policy_document = {"Version": "2012-10-17", "Statement": statements}

        return json.dumps(policy_document, indent=2)

    def _find_policy_arn_by_name(self, policy_name: str | None = None) -> str | None:
        """
        Search for a customer-managed policy by name (Scope='Local').
        Returns the policy ARN if found, else None.
        """
        search_name = policy_name or self.policy_name
        if search_name is None:
            return None

        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for p in page.get("Policies", []):
                if p.get("PolicyName") == search_name:
                    return str(p.get("Arn", ""))
        return None

    def _set_new_policy_version(
        self, policy_document: str, policy_arn: str | None = None
    ) -> None:
        """
        Create a new policy version and set it as default.
        Returns the new version ID.
        """
        target_arn = policy_arn or self.policy_arn
        if target_arn is None:
            raise ValueError("Policy ARN is required")

        resp = self.iam.create_policy_version(
            PolicyArn=target_arn,
            PolicyDocument=policy_document,
            SetAsDefault=True,
        )
        version_id = str(resp["PolicyVersion"]["VersionId"])
        print(
            f"Created new policy version {version_id} (set as default) for {target_arn}"
        )

        # Prune older versions if above limit
        self._prune_old_versions(keep=5, policy_arn=target_arn)

        return

    def _prune_old_versions(self, keep: int = 5, policy_arn: str | None = None) -> None:
        """
        IAM policies can have at most 5 versions. Delete oldest non-default versions
        until versions <= keep.
        """
        target_arn = policy_arn or self.policy_arn
        if target_arn is None:
            raise ValueError("Policy ARN is not set")
        resp = self.iam.list_policy_versions(PolicyArn=target_arn)
        versions = resp.get("Versions", [])

        # Separate non-default versions
        non_default = [v for v in versions if not v.get("IsDefaultVersion")]

        # Nothing to prune if total <= keep
        if len(versions) <= keep:
            return

        # Sort non-default by creation time (oldest first)
        def _parse(dt: Any) -> datetime:
            # dt is already a datetime in boto3 responses, but guard anyway
            return dt if isinstance(dt, datetime) else datetime.fromisoformat(str(dt))

        non_default_sorted = sorted(non_default, key=lambda v: _parse(v["CreateDate"]))
        to_delete = len(versions) - keep
        for v in non_default_sorted[:to_delete]:
            vid = v["VersionId"]
            self.iam.delete_policy_version(PolicyArn=target_arn, VersionId=vid)
            logger.info(f"Deleted old policy version {vid} on {target_arn}")

    def _load_policy_text(self) -> str:
        if not self.has_custom_policy or self.policy_file is None:
            raise ValueError("No custom policy configured")

        # Handle relative paths by resolving them relative to the config file directory
        policy_path = Path(self.policy_file)
        if not policy_path.is_absolute() and self.config_file_path:
            # Resolve relative path relative to the config file's directory
            config_dir = Path(self.config_file_path).parent
            policy_path = config_dir / policy_path

        with open(policy_path, encoding="utf-8") as f:
            text = f.read()
        # Simple token replacement
        return text.replace("{aws_account_id}", self.account_id)

    def _create_policy(self, policy_document: str) -> str:
        if not self.has_custom_policy or self.policy_name is None:
            raise ValueError("No custom policy configured")

        return self._create_policy_with_name(policy_document, self.policy_name)

    def _create_policy_with_name(self, policy_document: str, policy_name: str) -> str:
        """
        Create a policy with the given name and document.

        Args:
            policy_document: The policy document JSON string
            policy_name: The name for the policy

        Returns:
            str: The policy ARN
        """
        resp = self.iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_document,
            Description=f"Managed by script for policy '{policy_name}'",
        )
        arn = str(resp["Policy"]["Arn"])
        logger.info(f"Created policy: {arn}")
        return arn

    def _check_role_ready(self) -> bool:
        try:
            # Try to get the role to ensure it exists and is accessible
            self.iam.get_role(RoleName=self.role_name)
            # Check if the basic execution policy is attached
            attached_policies = self.iam.list_attached_role_policies(
                RoleName=self.role_name
            )
            basic_exec_policy_attached = any(
                policy["PolicyArn"]
                == "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                for policy in attached_policies.get("AttachedPolicies", [])
            )
            return basic_exec_policy_attached
        except ClientError:
            return False

    def deploy_policy(self) -> None:
        if not self.has_custom_policy and not self.has_auto_policy:
            logger.info(
                "No custom policy or auto policy configured, skipping policy deployment"
            )
            return

        # Deploy custom policy if it exists
        if self.has_custom_policy:
            self._deploy_single_policy(
                self._load_policy_text(), self.policy_name or "CustomPolicy", "custom"
            )

        # Deploy auto policy if it exists
        if self.has_auto_policy:
            self._deploy_single_policy(
                self._generate_auto_policy(), f"{self.role_name}AutoPolicy", "auto"
            )

    def _deploy_single_policy(
        self, policy_definition: str, policy_name: str, policy_type: str
    ) -> None:
        """
        Deploy a single policy and store its ARN.

        Args:
            policy_definition: The policy document JSON string
            policy_name: The name for the policy
            policy_type: Either "custom" or "auto" to determine which ARN to store
        """
        # Validate policy is valid JSON
        json.loads(policy_definition)
        if not policy_definition:
            raise ValueError("Policy definition is None")

        try:
            # Create the policy
            policy_arn = self._create_policy_with_name(policy_definition, policy_name)

            # Store the ARN based on policy type
            if policy_type == "custom":
                self.policy_arn = policy_arn
            elif policy_type == "auto":
                self.auto_policy_arn = policy_arn

        except ClientError as e:
            # Handle the case where the policy already exists
            if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                # Find existing policy ARN
                existing_arn = self._find_policy_arn_by_name(policy_name)
                if existing_arn is None:
                    raise Exception(
                        f"Policy {policy_name} already exists, but no ARN found"
                    )
                logger.info(
                    f"Policy {policy_name} already exists, updating instead: {existing_arn}"
                )
                self._set_new_policy_version(policy_definition, existing_arn)

                # Store the ARN based on policy type
                if policy_type == "custom":
                    self.policy_arn = existing_arn
                elif policy_type == "auto":
                    self.auto_policy_arn = existing_arn
            else:
                raise ClientError(e) from e
        except Exception as e:
            raise Exception(f"{e}")

    def deploy_role(self) -> None:
        # Define the trust policy
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        # Create the role with the trust policy
        try:
            resp = self.iam.create_role(
                RoleName=self.role_name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Description="Execution role for Lambda",
            )
            self.role_arn = str(resp["Role"]["Arn"])

            # Attach the basic execution policy
            self.iam.attach_role_policy(
                RoleName=self.role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )

        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                self.role_arn = self.iam.get_role(RoleName=self.role_name)["Role"][
                    "Arn"
                ]

                if self.role_arn is None or not isinstance(self.role_arn, str):
                    raise Exception("Role already exists, but no ARN found")
                logger.info(f"Role already exists: {self.role_arn}")
        except Exception as e:
            raise Exception(f"{e}")

        # Wait for the role to be ready in IAM
        retry_with_backoff(
            self._check_role_ready, max_retries=10, base_delay=2.0, max_delay=10.0
        )

        logger.info(f"Created role: {self.role_arn}")
        return

    def attach_policy_to_role(self, policy_arn: str, policy_name: str) -> None:
        """
        Attach a specific policy to the role.

        Args:
            policy_arn: The ARN of the policy to attach
            policy_name: The name of the policy for logging
        """
        try:
            self.iam.attach_role_policy(
                RoleName=self.role_name,
                PolicyArn=policy_arn,
            )
            logger.info(
                f"Attached policy {policy_name} ({policy_arn}) to role {self.role_name}"
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                logger.info(
                    f"Policy {policy_name} already attached to role {self.role_name}"
                )
            else:
                raise ClientError(e) from e
        except Exception as e:
            raise Exception(f"Failed to attach policy {policy_name} to role: {e}")

    def attach_all_policies(self) -> None:
        """
        Attach all applicable policies to the role:
        - Auto-generated policy (if parameters/secrets exist)
        - Custom policy (if policy_file exists)
        - Basic execution role (always attached)
        """
        policies_to_attach = []

        # 1. Custom policy (if exists)
        if self.has_custom_policy and self.policy_arn is not None:
            policies_to_attach.append((
                self.policy_arn,
                self.policy_name or "CustomPolicy",
            ))

        # 2. Auto-generated policy (if exists)
        if self.has_auto_policy and self.auto_policy_arn is not None:
            policies_to_attach.append((
                self.auto_policy_arn,
                f"{self.role_name}AutoPolicy",
            ))

        # 3. Basic execution role (always attach)
        basic_exec_policy_arn = (
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
        policies_to_attach.append((
            basic_exec_policy_arn,
            "AWSLambdaBasicExecutionRole",
        ))

        # Attach all policies
        for policy_info in policies_to_attach:
            policy_arn = policy_info[0]
            policy_name = policy_info[1]
            if isinstance(policy_arn, str) and isinstance(policy_name, str):
                self.attach_policy_to_role(policy_arn, policy_name)

    def deploy(self) -> None:
        self.deploy_policy()
        self.deploy_role()
        self.attach_all_policies()
        return


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments for IAM manager configuration.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="AWS IAM Manager - Deploy IAM policies and roles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Configuration file
    parser.add_argument(
        "--config-file",
        "-c",
        required=True,
        help="Path to JSON configuration file",
    )

    return parser.parse_args()


def main() -> int:
    """
    Main function to run the IAM manager from command line.

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        # Parse command line arguments
        args = parse_args()

        # Load configuration from file
        config = get_config(args.config_file)

        # Create IAM manager with configuration data
        iam_manager = IAMManager(
            role_name=config.role_name,
            account_id=config.account_id,
            config=config,
            policy_name=getattr(config, "policy_name", None),
            policy_file=getattr(config, "policy_file", None),
            config_file_path=args.config_file,
        )

        logger.info("Starting IAM deployment...")
        logger.info(f"Role: {config.role_name}")
        logger.info(f"Account ID: {config.account_id}")

        if hasattr(config, "policy_name") and config.policy_name:
            logger.info(f"Custom Policy: {config.policy_name}")

        if hasattr(config, "parameters") and config.parameters:
            # Count regular parameters vs secrets
            regular_params = sum(
                1 for p in config.parameters if p.get("Type") != "SecureString"
            )
            secret_params = sum(
                1 for p in config.parameters if p.get("Type") == "SecureString"
            )

            if regular_params > 0:
                logger.info(f"Auto Policy: Generated from {regular_params} parameters")
            if secret_params > 0:
                logger.info(f"Auto Policy: Generated from {secret_params} secrets")

        if not (hasattr(config, "policy_name") and config.policy_name) and not (
            hasattr(config, "parameters") and config.parameters
        ):
            logger.info(
                "No custom policy or parameters configured - only basic execution role will be attached"
            )

        # Deploy the policy and role
        iam_manager.deploy()

        logger.info("IAM deployment completed successfully!")
        return 0

    except FileNotFoundError as e:
        logger.error(f"Configuration file not found: {e}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        return 1
    except KeyError as e:
        logger.error(f"Missing required configuration field: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error during IAM deployment: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
