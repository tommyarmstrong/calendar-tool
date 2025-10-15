#!/usr/bin/env python3
"""
Create or update an AWS IAM policy from a JSON definition.

Usage:
  python put_iam_policy.py --policy-name AllowReadProdSecrets \
    --policy-definition iam_secrets_policy.json
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError


def load_policy_text(path: str, account_id: str) -> str:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # Simple token replacement
    return text.replace("{aws_account_id}", account_id)


def get_account_id() -> str:
    sts = boto3.client("sts")
    return str(sts.get_caller_identity()["Account"])


def find_policy_arn_by_name(iam: Any, policy_name: str) -> str | None:
    """
    Search for a customer-managed policy by name (Scope='Local').
    Returns the policy ARN if found, else None.
    """
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for p in page.get("Policies", []):
            if p.get("PolicyName") == policy_name:
                return str(p.get("Arn", ""))
    return None


def create_policy(iam: Any, policy_name: str, policy_document: str) -> str:
    resp = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=policy_document,
        Description=f"Managed by script for policy '{policy_name}'",
    )
    arn = str(resp["Policy"]["Arn"])
    print(f"✅ Created policy: {arn}")
    return arn


def set_new_policy_version(iam: Any, policy_arn: str, policy_document: str) -> str:
    """
    Create a new policy version and set it as default.
    Returns the new version ID.
    """
    resp = iam.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=policy_document,
        SetAsDefault=True,
    )
    version_id = str(resp["PolicyVersion"]["VersionId"])
    print(f"🔁 Created new policy version {version_id} (set as default) for {policy_arn}")
    return version_id


def prune_old_versions(iam: Any, policy_arn: str, keep: int = 5) -> None:
    """
    IAM policies can have at most 5 versions. Delete oldest non-default versions
    until versions <= keep.
    """
    resp = iam.list_policy_versions(PolicyArn=policy_arn)
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
        iam.delete_policy_version(PolicyArn=policy_arn, VersionId=vid)
        print(f"🧹 Deleted old policy version {vid} on {policy_arn}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or update an IAM policy from JSON.")

    # Create mutually exclusive group
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--policy-name", help="Name of the IAM policy to create/update")
    group.add_argument(
        "--lambda-config-file",
        help="JSON config file containing 'policy_name' and 'policy_file' keys",
    )

    parser.add_argument(
        "--policy-definition",
        help="Path to the JSON policy document (supports {aws_account_id} placeholder)",
    )
    args = parser.parse_args()

    # Handle lambda config file or direct arguments
    policy_definition: str
    if args.lambda_config_file:
        with open(args.lambda_config_file) as f:
            config = json.load(f)
        policy_name = config["policy_name"]
        policy_definition = config["policy_file"]

        # If policy_file is a relative path, make it relative to the config file directory
        import os

        if not os.path.isabs(policy_definition):
            config_dir = os.path.dirname(os.path.abspath(args.lambda_config_file))
            policy_definition = os.path.join(config_dir, policy_definition)
    else:
        if not args.policy_definition:
            parser.error("--policy-definition is required when using --policy-name")
        policy_name = args.policy_name
        policy_definition = args.policy_definition

    try:
        account_id = get_account_id()

        policy_document_text = load_policy_text(policy_definition, account_id)

        # Validate the JSON early (throws if invalid)
        try:
            json.loads(policy_document_text)
        except json.JSONDecodeError as e:
            print(f"ERROR: Policy document is not valid JSON: {e}")
            return 2

        iam = boto3.client("iam")

        arn = find_policy_arn_by_name(iam, policy_name)
        print(f"ARN: {arn}")
        if arn is None:
            # Try to create fresh
            try:
                arn = create_policy(iam, policy_name, policy_document_text)
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                    # Race condition: just created by another process; find it again
                    arn = find_policy_arn_by_name(iam, policy_name)
                    if arn is None:
                        raise
                    print(f"ℹ️ Policy already exists, updating instead: {arn}")
                    set_new_policy_version(iam, arn, policy_document_text)
                else:
                    raise
        else:
            # Update existing by adding a new default version
            set_new_policy_version(iam, arn, policy_document_text)

        # Prune older versions if above limit
        prune_old_versions(iam, arn, keep=5)

        print(f"✅ Policy ready: {arn}")
        return 0

    except ClientError as e:
        print(f"AWS ClientError: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
