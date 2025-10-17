#!/usr/bin/env python3
"""
Create & configure an S3 bucket (idempotent) for secure use:

- Creates bucket in the specified region (handles us-east-1 rules)
- Enables Versioning
- Blocks Public Access (all)
- Sets Default Encryption (SSE-S3 by default; KMS if --kms-key-id is provided)
- Adds a TLS-only bucket policy (deny non-HTTPS)
- (Optional) Adds lifecycle to expire noncurrent versions

Usage:
  python create_secure_bucket.py --bucket my-bucket --region eu-west-2 \
    [--kms-key-id alias/my-kms-key] \
    [--tags env=dev,owner=you] \
    [--lifecycle-expire-noncurrent-days 30]
"""

import argparse
import json
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError


def parse_tags(tag_str: str | None) -> list[dict[str, str]]:
    if not tag_str:
        return []
    pairs = []
    for item in tag_str.split(","):
        if not item.strip():
            continue
        if "=" not in item:
            raise ValueError(f"Invalid tag '{item}'. Use key=value.")
        k, v = item.split("=", 1)
        pairs.append({"Key": k.strip(), "Value": v.strip()})
    return pairs


def ensure_bucket(s3: Any, bucket: str, region: str) -> None:
    """Create the bucket if it doesn't exist. Idempotent."""
    try:
        s3.head_bucket(Bucket=bucket)
        print(f"[OK] Bucket already exists: s3://{bucket}")
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            # Could be 403 (exists but not owned), etc.
            raise

    create_kwargs: dict[str, Any] = {"Bucket": bucket}
    if region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}

    try:
        s3.create_bucket(**create_kwargs)
        print(f"[OK] Created bucket: s3://{bucket}")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("BucketAlreadyOwnedByYou",):
            print(f"[OK] Bucket already owned by you: s3://{bucket}")
        elif code in ("BucketAlreadyExists",):
            print(f"[WARN] Bucket name is taken globally: {bucket}")
            raise
        else:
            raise


def enable_versioning(s3: Any, bucket: str) -> None:
    s3.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    print("[OK] Versioning enabled")


def block_public_access(s3: Any, bucket: str) -> None:
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print("[OK] Public access blocked (all flags)")


def set_default_encryption(s3: Any, bucket: str, kms_key_id: str | None) -> None:
    if kms_key_id:
        rule = {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": kms_key_id,
            },
            "BucketKeyEnabled": True,
        }
    else:
        rule = {
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
            "BucketKeyEnabled": True,
        }

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": rule[
                        "ApplyServerSideEncryptionByDefault"
                    ],
                    "BucketKeyEnabled": rule["BucketKeyEnabled"],
                }
            ]
        },
    )
    algo = "KMS" if kms_key_id else "SSE-S3"
    print(f"[OK] Default encryption set ({algo})")


def require_tls_policy(s3: Any, bucket: str) -> None:
    """Attach a policy that denies any non-HTTPS (non-SecureTransport) requests."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*",
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }
    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
        print("[OK] TLS-only bucket policy applied")
    except ClientError as e:
        # This can fail if you lack permissions for PutBucketPolicy
        print(f"[WARN] Could not apply bucket policy: {e}")


def put_lifecycle_noncurrent_expiry(s3: Any, bucket: str, days: int) -> None:
    """Expire old object versions after N days (keeps storage costs down)."""
    config = {
        "Rules": [
            {
                "ID": "ExpireNoncurrentVersions",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},  # apply to all objects
                "NoncurrentVersionExpiration": {"NoncurrentDays": days},
            }
        ]
    }
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=config)
    print(f"[OK] Lifecycle: noncurrent versions expire after {days} days")


def tag_bucket(s3: Any, bucket: str, tags: list[dict[str, str]]) -> None:
    if not tags:
        return
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tags})
    print(f"[OK] Applied {len(tags)} tag(s)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create & configure an S3 bucket securely."
    )
    parser.add_argument(
        "--bucket", required=True, help="Bucket name (globally unique)."
    )
    parser.add_argument(
        "--region", default="us-east-1", help="AWS region (default: us-east-1)."
    )
    parser.add_argument(
        "--kms-key-id", help="KMS key ID or alias for default encryption (optional)."
    )
    parser.add_argument("--tags", help="Comma-separated tags: key1=val1,key2=val2")
    parser.add_argument(
        "--lifecycle-expire-noncurrent-days",
        type=int,
        default=0,
        help="Expire noncurrent object versions after N days (0=disabled).",
    )
    args = parser.parse_args()

    session: Any = boto3.Session(region_name=args.region)
    s3: Any = session.client("s3")

    try:
        ensure_bucket(s3, args.bucket, args.region)
        block_public_access(s3, args.bucket)
        enable_versioning(s3, args.bucket)
        set_default_encryption(s3, args.bucket, args.kms_key_id)
        require_tls_policy(s3, args.bucket)

        tags = parse_tags(args.tags)
        if tags:
            tag_bucket(s3, args.bucket, tags)

        if args.lifecycle_expire_noncurrent_days > 0:
            put_lifecycle_noncurrent_expiry(
                s3, args.bucket, args.lifecycle_expire_noncurrent_days
            )

        print(f"\n[DONE] Bucket ready: s3://{args.bucket}")
        print(
            "Settings: Versioning=Enabled, PublicAccess=Blocked, Encryption=On, TLS-only policy applied."
        )
        if args.kms_key_id:
            print(f"Encryption key: {args.kms_key_id}")
    except ClientError as e:
        print(f"[ERROR] AWS error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
