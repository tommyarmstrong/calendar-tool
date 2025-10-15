import json
import time
from datetime import datetime
from typing import Any, Callable

import boto3
from aws_config_manager import create_logger
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
        self, policy_name: str, policy_file: str, role_name: str, account_id: str
    ):
        self.policy_name = policy_name
        self.policy_file = policy_file
        self.role_name = role_name
        self.account_id = account_id
        self.policy_arn: str | None = None

        self.iam = boto3.client("iam")

    def _find_policy_arn_by_name(self) -> str | None:
        """
        Search for a customer-managed policy by name (Scope='Local').
        Returns the policy ARN if found, else None.
        """
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for p in page.get("Policies", []):
                if p.get("PolicyName") == self.policy_name:
                    return str(p.get("Arn", ""))
        return None

    def _set_new_policy_version(self, policy_document: str) -> None:
        """
        Create a new policy version and set it as default.
        Returns the new version ID.
        """
        resp = self.iam.create_policy_version(
            PolicyArn=self.policy_arn,
            PolicyDocument=policy_document,
            SetAsDefault=True,
        )
        version_id = str(resp["PolicyVersion"]["VersionId"])
        print(
            f"Created new policy version {version_id} (set as default) for {self.policy_arn}"
        )

        # Prune older versions if above limit
        self._prune_old_versions(keep=5)

        return

    def _prune_old_versions(self, keep: int = 5) -> None:
        """
        IAM policies can have at most 5 versions. Delete oldest non-default versions
        until versions <= keep.
        """
        if self.policy_arn is None:
            raise ValueError("Policy ARN is not set")
        resp = self.iam.list_policy_versions(PolicyArn=self.policy_arn)
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
            self.iam.delete_policy_version(PolicyArn=self.policy_arn, VersionId=vid)
            logger.info(f"Deleted old policy version {vid} on {self.policy_arn}")

    def _load_policy_text(self) -> str:
        with open(self.policy_file, encoding="utf-8") as f:
            text = f.read()
        # Simple token replacement
        return text.replace("{aws_account_id}", self.account_id)

    def _create_policy(self, policy_document: str) -> str:
        resp = self.iam.create_policy(
            PolicyName=self.policy_name,
            PolicyDocument=policy_document,
            Description=f"Managed by script for policy '{self.policy_name}'",
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
        # Load the policy text and validate it is valid JSON
        policy_definition = self._load_policy_text()
        json.loads(policy_definition)
        if not policy_definition:
            raise ValueError("Policy definition is None")

        try:
            # Create the policy
            self.policy_arn = self._create_policy(policy_definition)

        except ClientError as e:
            # Handle the case where the policy already exists
            if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                self.policy_arn = self._find_policy_arn_by_name()
                if self.policy_arn is None:
                    raise Exception("Policy already exists, but no ARN found")
                logger.info(
                    f"Policy already exists, updating instead: {self.policy_arn}"
                )
                self._set_new_policy_version(policy_definition)
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

    def deploy(self) -> None:
        self.deploy_policy()
        self.deploy_role()
        return
