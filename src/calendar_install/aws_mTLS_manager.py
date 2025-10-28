#!/usr/bin/env python3
"""
AWS mTLS Manager

This module provides a comprehensive manager for AWS mTLS (mutual TLS) operations
including certificate management, S3 truststore management, and API Gateway configuration.
"""

import argparse
import json
import random
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

import boto3
from aws_config_manager import create_logger
from botocore.exceptions import ClientError

# Create logger for the mTLS manager
logger = create_logger(logger_name="aws_deployment", log_level="INFO")


def retry_with_backoff(
    func: Callable[[], Any], max_retries: int = 5, base_delay: float = 1.0
) -> Any:
    """Retry a function with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if (
                error_code in ["TooManyRequestsException", "ThrottlingException"]
                and attempt < max_retries - 1
            ):
                delay = base_delay * (2**attempt) + random.uniform(0, 1)
                logger.warning(
                    f"Rate limited, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})"
                )
                time.sleep(delay)
                continue
            raise
        except Exception as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2**attempt) + random.uniform(0, 1)
                logger.warning(
                    f"Error occurred, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries}): {e}"
                )
                time.sleep(delay)
                continue
            raise
    raise Exception(f"Max retries ({max_retries}) exceeded")


class APIDomainManager:
    """Manages API Gateway v2 custom domain with mTLS configuration."""

    def __init__(
        self,
        domain: str,
        cert_arn: str,
        truststore_uri: str,
        truststore_version: str,
        region: str = "us-east-1",
    ) -> None:
        """
        Initialize the API Domain Manager.

        Args:
            domain: Custom domain name (e.g., mcp.example.com)
            cert_arn: ACM certificate ARN
            truststore_uri: S3 URI to PEM truststore
            truststore_version: S3 object version ID for the truststore
            region: AWS region (default: us-east-1)
        """
        self.domain = domain
        self.cert_arn = cert_arn
        self.truststore_uri = truststore_uri
        self.truststore_version = truststore_version
        self.region = region

        # Initialize AWS API Gateway v2 client
        self.apigatewayv2 = boto3.client("apigatewayv2", region_name=self.region)

    def validate_s3_uri(self, uri: str) -> None:
        """Validate S3 URI format."""
        if not re.match(r"^s3://[^/]+/.+$", uri):
            raise ValueError("TRUSTSTORE_URI must be like s3://bucket/key.pem")

    def upsert_domain(self) -> tuple[str, str | None, dict[str, Any]]:
        """Create or update API Gateway v2 custom domain with mTLS."""
        cfg = {
            "CertificateArn": self.cert_arn,
            "EndpointType": "REGIONAL",
            "SecurityPolicy": "TLS_1_2",
        }
        mtls = {
            "TruststoreUri": self.truststore_uri,
            "TruststoreVersion": self.truststore_version,
        }

        # Try to see if domain already exists
        try:
            _ = self.apigatewayv2.get_domain_name(DomainName=self.domain)
            action = "updated"

            # Update domain configuration first with retry
            def update_domain_config() -> Any:
                return self.apigatewayv2.update_domain_name(
                    DomainName=self.domain,
                    DomainNameConfigurations=[cfg],
                )

            resp = retry_with_backoff(update_domain_config)

            # Wait longer before updating mTLS to avoid concurrent update error
            time.sleep(5)

            # Update mTLS configuration separately with retry
            def update_mtls_config() -> Any:
                return self.apigatewayv2.update_domain_name(
                    DomainName=self.domain,
                    MutualTlsAuthentication=mtls,
                )

            resp = retry_with_backoff(update_mtls_config)

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "NotFoundException":

                def create_domain() -> Any:
                    return self.apigatewayv2.create_domain_name(
                        DomainName=self.domain,
                        DomainNameConfigurations=[cfg],
                        MutualTlsAuthentication=mtls,
                    )

                resp = retry_with_backoff(create_domain)
                action = "created"
            else:
                raise

        # Extract the ApiGatewayDomainName you must CNAME to
        agw_domain = None
        dn_cfgs = resp.get("DomainNameConfigurations", []) or []
        if dn_cfgs:
            # For HTTP API regional custom domains, ApiGatewayDomainName is present
            agw_domain = dn_cfgs[0].get("ApiGatewayDomainName")

        return action, agw_domain, resp

    def deploy(self) -> None:
        """Deploy and configure the API Gateway v2 custom domain with mTLS."""
        try:
            self.validate_s3_uri(self.truststore_uri)
            action, agw_domain, resp = self.upsert_domain()

            logger.info(f"Custom domain {action}: {self.domain}")
            if agw_domain:
                logger.info(
                    f"Create a CNAME record in your DNS provider for {self.domain} to {agw_domain}"
                )
            else:
                logger.warning(
                    "Could not determine ApiGatewayDomainName from response. Full response follows:"
                )
                logger.warning(str(resp))

            logger.info(
                f"Your MCP API is now accessible via https://{self.domain}/ ... (mTLS enforced only on the custom domain)."
            )

        except Exception as e:
            logger.error(f"Failed to deploy API domain: {e}")
            raise


class CertificateBucketManager:
    """Manages the creation and configuration of S3 buckets for certificate storage."""

    def __init__(
        self,
        bucket: str,
        region: str,
        kms_key_id: str | None = None,
        tags: str | None = None,
        lifecycle_expire_noncurrent_days: int = 0,
        ca_truststore_file: str = "certificates/truststore.pem",
    ) -> None:
        """
        Initialize the CertificateBucketManager.

        Args:
            bucket: S3 bucket name (globally unique)
            region: AWS region
            kms_key_id: KMS key ID or alias for default encryption (optional)
            tags: Comma-separated tags: key1=val1,key2=val2
            lifecycle_expire_noncurrent_days: Expire noncurrent object versions after N days (0=disabled)
            ca_truststore_file: Path to the CA truststore file to upload (default: certificates/truststore.pem)
        """
        self.bucket = bucket
        self.region = region
        self.kms_key_id = kms_key_id
        self.tags = tags
        self.lifecycle_expire_noncurrent_days = lifecycle_expire_noncurrent_days
        self.ca_truststore_file = ca_truststore_file

        # Initialize AWS session and client
        self.s3 = boto3.client("s3")

    @staticmethod
    def parse_tags(tag_str: str | None) -> list[dict[str, str]]:
        """Parse comma-separated tags string into list of key-value dictionaries."""
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

    def ensure_bucket(self) -> None:
        """Create the bucket if it doesn't exist. Idempotent."""
        try:
            self.s3.head_bucket(Bucket=self.bucket)
            self.bucket_arn = f"s3://{self.bucket}"
            logger.info(f"Bucket already exists: {self.bucket_arn}")
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code not in ("404", "NoSuchBucket", "NotFound"):
                # Could be 403 (exists but not owned), etc.
                raise

        create_kwargs: dict[str, Any] = {"Bucket": self.bucket}
        if self.region != "us-east-1":
            create_kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": self.region
            }

        try:
            self.s3.create_bucket(**create_kwargs)
            self.bucket_arn = f"s3://{self.bucket}"
            logger.info(f"Created bucket: {self.bucket_arn}")
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("BucketAlreadyOwnedByYou",):
                logger.info(f"Bucket already owned by you: s3://{self.bucket}")
            elif code in ("BucketAlreadyExists",):
                logger.warning(f"Bucket name is taken globally: {self.bucket}")
                raise
            else:
                raise

    def enable_versioning(self) -> None:
        """Enable versioning on the bucket."""
        self.s3.put_bucket_versioning(
            Bucket=self.bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
        logger.info("Versioning enabled")

    def block_public_access(self) -> None:
        """Block all public access to the bucket."""
        self.s3.put_public_access_block(
            Bucket=self.bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        logger.info("Public access blocked (all flags)")

    def set_default_encryption(self) -> None:
        """Set default encryption on the bucket."""
        if self.kms_key_id:
            rule = {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": self.kms_key_id,
                },
                "BucketKeyEnabled": True,
            }
        else:
            rule = {
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                "BucketKeyEnabled": True,
            }

        self.s3.put_bucket_encryption(
            Bucket=self.bucket,
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
        algo = "KMS" if self.kms_key_id else "SSE-S3"
        logger.info(f"Default encryption set ({algo})")

    def require_tls_policy(self) -> None:
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
                        f"arn:aws:s3:::{self.bucket}",
                        f"arn:aws:s3:::{self.bucket}/*",
                    ],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }
        try:
            self.s3.put_bucket_policy(Bucket=self.bucket, Policy=json.dumps(policy))
            logger.info("TLS-only bucket policy applied")
        except ClientError as e:
            # This can fail if you lack permissions for PutBucketPolicy
            logger.warning(f"Could not apply bucket policy: {e}")

    def put_lifecycle_noncurrent_expiry(self) -> None:
        """Expire old object versions after configured days (keeps storage costs down)."""
        if self.lifecycle_expire_noncurrent_days <= 0:
            return

        config = {
            "Rules": [
                {
                    "ID": "ExpireNoncurrentVersions",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},  # apply to all objects
                    "NoncurrentVersionExpiration": {
                        "NoncurrentDays": self.lifecycle_expire_noncurrent_days
                    },
                }
            ]
        }
        self.s3.put_bucket_lifecycle_configuration(
            Bucket=self.bucket, LifecycleConfiguration=config
        )
        logger.info(
            f"Lifecycle: noncurrent versions expire after {self.lifecycle_expire_noncurrent_days} days"
        )

    def tag_bucket(self) -> None:
        """Apply tags to the bucket."""
        parsed_tags = self.parse_tags(self.tags)
        if not parsed_tags:
            return
        self.s3.put_bucket_tagging(Bucket=self.bucket, Tagging={"TagSet": parsed_tags})
        logger.info(f"Applied {len(parsed_tags)} tag(s)")

    def upload_certificate(self, certificate_path: str | None = None) -> None:
        """
        Upload a certificate file to the S3 bucket with appropriate security configurations.

        Args:
            certificate_path: Path to the certificate file to upload (defaults to ca_truststore_file)
        """
        if certificate_path is None:
            certificate_path = self.ca_truststore_file
        cert_path = Path(certificate_path)

        if not cert_path.exists():
            raise FileNotFoundError(f"Certificate file not found: {certificate_path}")

        if not cert_path.is_file():
            raise ValueError(f"Path is not a file: {certificate_path}")

        # Determine the appropriate folder based on file extension
        file_extension = cert_path.suffix.lower()
        if file_extension in [".crt", ".pem", ".cer"]:
            folder = "certificates"
        elif file_extension in [".key"]:
            folder = "private-keys"
        elif file_extension in [".p12", ".pfx"]:
            folder = "p12-bundles"
        elif file_extension in [".jks", ".keystore"]:
            folder = "keystores"
        else:
            folder = "misc"

        # Create the S3 key with folder structure
        s3_key = f"{folder}/{cert_path.name}"

        try:
            # Read the certificate file
            with open(cert_path, "rb") as cert_file:
                cert_data = cert_file.read()

            # Upload with security configurations
            content_type = self._get_content_type(file_extension)
            server_side_encryption = "AES256" if not self.kms_key_id else "aws:kms"
            metadata = {
                "original-filename": cert_path.name,
                "upload-timestamp": str(int(cert_path.stat().st_mtime)),
                "file-extension": file_extension,
            }

            # Upload the file
            if self.kms_key_id:
                response = self.s3.put_object(
                    Bucket=self.bucket,
                    Key=s3_key,
                    Body=cert_data,
                    ContentType=content_type,
                    ServerSideEncryption=server_side_encryption,
                    SSEKMSKeyId=self.kms_key_id,
                    Metadata=metadata,
                )
            else:
                response = self.s3.put_object(
                    Bucket=self.bucket,
                    Key=s3_key,
                    Body=cert_data,
                    ContentType=content_type,
                    ServerSideEncryption=server_side_encryption,
                    Metadata=metadata,
                )

            logger.info(
                f"Successfully uploaded certificate: s3://{self.bucket}/{s3_key}"
            )
            logger.info(f"ETag: {response.get('ETag', 'N/A')}")
            logger.info(f"Version ID: {response.get('VersionId', 'N/A')}")

            self.truststore_version = self.get_latest_certificate_version(s3_key)

        except Exception as e:
            logger.error(f"Failed to upload certificate {certificate_path}: {e}")
            raise

    def _get_content_type(self, file_extension: str) -> str:
        """Get the appropriate MIME type for the certificate file."""
        content_types = {
            ".crt": "application/x-x509-ca-cert",
            ".pem": "application/x-pem-file",
            ".cer": "application/x-x509-ca-cert",
            ".key": "application/x-pem-file",
            ".p12": "application/x-pkcs12",
            ".pfx": "application/x-pkcs12",
            ".jks": "application/x-java-keystore",
            ".keystore": "application/x-java-keystore",
        }
        return content_types.get(file_extension, "application/octet-stream")

    def get_latest_certificate_version(self, key: str) -> str | None:
        """
        Return the VersionId of the latest version of `s3://bucket/key`.
        If bucket versioning is disabled or the object doesn't exist, returns None.
        """

        try:
            # List object versions under this key and pick the one marked IsLatest
            paginator = self.s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=key):
                for v in page.get("Versions", []):
                    if v["Key"] == key and v.get("IsLatest"):
                        version_id = v.get("VersionId")
                        return version_id if version_id is not None else None
            # If we got here, either no versions or not found
            return None
        except ClientError as e:
            # NoSuchBucket / AccessDenied / etc.
            logger.error(e)
            return None

    def deploy(self) -> None:
        """Deploy and configure the S3 bucket with all security settings."""
        try:
            self.ensure_bucket()
            self.block_public_access()
            self.enable_versioning()
            self.set_default_encryption()
            self.require_tls_policy()
            self.tag_bucket()
            self.put_lifecycle_noncurrent_expiry()
            self.upload_certificate()

            logger.info(f"Bucket ready: s3://{self.bucket}")
            logger.info(
                "Settings: Versioning=Enabled, PublicAccess=Blocked, Encryption=On, TLS-only policy applied."
            )
            if self.kms_key_id:
                logger.info(f"Encryption key: {self.kms_key_id}")
        except ClientError as e:
            logger.error(f"AWS error: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            sys.exit(1)


class ACMCertManager:
    """Manages AWS Certificate Manager (ACM) certificate operations."""

    def __init__(
        self,
        domain: str,
        region: str = "us-east-1",
        sans: list[str] | None = None,
        transparency_enabled: bool = True,
        key_algorithm: str = "RSA_2048",
        tags: list[dict[str, str]] | None = None,
    ) -> None:
        """
        Initialize the AWS Certificate Manager.

        Args:
            domain: Primary domain name (e.g., mcp.example.com or *.example.com)
            region: AWS region for the ACM client (default: us-east-1)
            sans: List of Subject Alternative Names (optional)
            transparency_enabled: Whether to enable Certificate Transparency logging
            key_algorithm: Key algorithm (RSA_2048, RSA_3072, RSA_4096, EC_prime256v1, EC_secp384r1)
            tags: List of tags to apply to the certificate (optional)
        """
        self.domain = domain
        self.region = region
        self.sans = sans or []
        self.transparency_enabled = transparency_enabled
        self.key_algorithm = key_algorithm
        self.tags = tags or []

        # Initialize boto3 ACM client with specified region
        self.acm = boto3.client("acm", region_name=self.region)

    def deploy(self) -> str:
        """
        Deploy and request the ACM certificate with DNS validation.

        Returns:
            Certificate ARN
        """
        try:
            self.cert_arn = self.request_certificate()
            logger.info("Requested certificate:")
            logger.info(f"     ARN: {self.cert_arn}")

            # Show DNS records to add for validation
            records = self.get_dns_records_for_validation()
            if records:
                logger.info(
                    "ACTION REQUIRED: Add the following DNS CNAME record(s) at your DNS provider:"
                )
                for rr in records:
                    logger.info(f"  - Name : {rr['Name']}")
                    logger.info(f"    Type : {rr['Type']}")
                    logger.info(f"    Value: {rr['Value']}")
                logger.info(
                    "After propagating DNS, ACM will validate and issue the cert automatically."
                )
            else:
                logger.info(
                    "No DNS records returned yet. Re-run describe later to fetch CNAMEs."
                )

            return self.cert_arn

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            error_message = e.response.get("Error", {}).get("Message")
            logger.error(f"AWS ClientError {error_code}: {error_message}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise

    def wait_for_issuance(
        self, cert_arn: str, timeout_sec: int = 900, poll_sec: int = 10
    ) -> str:
        """
        Poll ACM until the certificate is ISSUED (or FAILED/timeout).
        Returns the final status.

        Args:
            cert_arn: Certificate ARN to monitor
            timeout_sec: Maximum seconds to wait (default: 900)
            poll_sec: Seconds between polls (default: 10)

        Returns:
            Final certificate status
        """
        start = time.time()
        status = "PENDING_VALIDATION"
        while True:
            desc = self.acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
            status = desc.get("Status", "UNKNOWN")
            if status in ("ISSUED", "FAILED", "REVOKED"):
                return status
            if time.time() - start > timeout_sec:
                return status
            time.sleep(poll_sec)

    @staticmethod
    def parse_sans(sans: str | None) -> list[str]:
        """Parse comma-separated SANs string into list of strings."""
        if not sans:
            return []
        return [s.strip() for s in sans.split(",") if s.strip()]

    @staticmethod
    def parse_tags(tag_str: str | None) -> list[dict[str, str]]:
        """Parse comma-separated tags string into list of key-value dictionaries."""
        if not tag_str:
            return []
        out = []
        for kv in tag_str.split(","):
            kv = kv.strip()
            if not kv:
                continue
            if "=" not in kv:
                raise ValueError(f"Invalid tag '{kv}'. Use key=value.")
            k, v = kv.split("=", 1)
            out.append({"Key": k.strip(), "Value": v.strip()})
        return out

    def request_certificate(self) -> str:
        """
        Request a public certificate with DNS validation.
        Returns the CertificateArn.
        """
        options = {
            "CertificateTransparencyLoggingPreference": "ENABLED"
            if self.transparency_enabled
            else "DISABLED"
        }

        params: dict[str, Any] = {
            "DomainName": self.domain,
            "ValidationMethod": "DNS",
            "Options": options,
            "KeyAlgorithm": self.key_algorithm,
            "Tags": self.tags or [],
        }
        if self.sans:
            params["SubjectAlternativeNames"] = self.sans

        resp = self.acm.request_certificate(**params)
        cert_arn: str = resp["CertificateArn"]
        return cert_arn

    def get_dns_records_for_validation(self) -> list[dict[str, str]]:
        """
        Returns a list of DNS records you must add:
        [{'Name': '...', 'Type': 'CNAME', 'Value': '...'}, ...]
        """
        desc = self.acm.describe_certificate(CertificateArn=self.cert_arn)[
            "Certificate"
        ]
        records = []
        for dvo in desc.get("DomainValidationOptions", []):
            rr = dvo.get("ResourceRecord")
            if rr:
                records.append({
                    "Name": rr["Name"],
                    "Type": rr["Type"],
                    "Value": rr["Value"],
                })
        return records


class APIMappingManager:
    def __init__(
        self,
        domain_name: str,
        api_name: str = "calendar_mcp",
        stage: str = "prod",
        base_path: str | None = None,
    ) -> None:
        self.domain_name = domain_name
        self.api_name = api_name
        self.stage = stage
        self.base_path = base_path

        self.apigw = boto3.client("apigatewayv2")
        self.api_id = self.find_api_id_by_name()

        if self.api_id is None:
            raise ValueError(f"API {self.api_name} not found")

    def find_api_id_by_name(self) -> str | None:
        paginator = self.apigw.get_paginator("get_apis")
        for page in paginator.paginate():
            for api in page.get("Items", []):
                if api.get("Name") == self.api_name:
                    api_id = api.get("ApiId")
                    return api_id if api_id is not None else None
        return None

    def upsert_api_mapping(self) -> str:
        """
        Create (or update) an API mapping to bind `domain_name` to `api_id`/`stage`.

        Returns the API mapping id.

        Works with API Gateway v2 (HTTP APIs). For REST APIs use apigateway (v1) instead.

        Required IAM permissions:
        - apigatewayv2:GetApiMappings
        - apigatewayv2:CreateApiMapping
        - apigatewayv2:UpdateApiMapping
        """
        assert self.api_id is not None

        try:
            # 1) Look for an existing mapping with the same base path
            response = self.apigw.get_api_mappings(DomainName=self.domain_name)
            existing = None
            for m in response.get("Items", []):
                if (m.get("ApiMappingKey") or "") == (self.base_path or ""):
                    existing = m
                    break

            if existing:
                # If already mapped to the same API/stage, return; otherwise update it
                if (
                    existing.get("ApiId") == self.api_id
                    and existing.get("Stage") == self.stage
                ):
                    mapping_id = existing.get("ApiMappingId")
                    return mapping_id if mapping_id is not None else ""

                resp = self.apigw.update_api_mapping(
                    ApiMappingId=existing["ApiMappingId"],
                    DomainName=self.domain_name,
                    ApiId=self.api_id,
                    Stage=self.stage,
                    ApiMappingKey=self.base_path or "",
                )
                mapping_id = resp.get("ApiMappingId")
                return mapping_id if mapping_id is not None else ""

            # 2) Create a new mapping
            resp = self.apigw.create_api_mapping(
                DomainName=self.domain_name,
                ApiId=self.api_id,
                Stage=self.stage,
                ApiMappingKey=self.base_path or "",
            )
            mapping_id = resp.get("ApiMappingId")
            return mapping_id if mapping_id is not None else ""

        except ClientError as e:
            raise RuntimeError(
                f"Failed to upsert API mapping for domain '{self.domain_name}' (api={self.api_id}, stage={self.stage}, base_path={self.base_path!r}): {e}"
            ) from e


class AWS_mTLS_Manager:
    """Manages AWS mTLS operations including certificates, truststores, and API Gateway configuration."""

    def __init__(self, region: str = "us-east-1") -> None:
        """
        Initialize the AWS mTLS Manager.

        Args:
            region: AWS region (default: us-east-1)
        """
        self.region = region
        logger.info(f"Initialized AWS mTLS Manager for region: {self.region}")

    def deploy(self) -> None:
        """Deploy mTLS infrastructure components."""
        logger.info("Starting mTLS infrastructure deployment...")
        # TODO: Implement deployment logic
        logger.info("mTLS infrastructure deployment completed")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the mTLS manager tool."""
    parser = argparse.ArgumentParser(
        description="Manage AWS mTLS infrastructure components"
    )
    parser.add_argument(
        "--bucket", required=True, help="Bucket name (globally unique)."
    )
    parser.add_argument(
        "--domain", required=True, help="Domain name (e.g., mcp.example.com)."
    )
    parser.add_argument(
        "--region_name", default="us-east-1", help="AWS Region (default: us-east-1)."
    )
    parser.add_argument("--sans", help="Comma-separated Subject Alternative Names.")
    parser.add_argument(
        "--kms-key-id", help="KMS key ID or alias for default encryption (optional)."
    )
    parser.add_argument(
        "--tags",
        default="app=calendar-agent",
        help="Comma-separated tags: key1=val1,key2=val2 (default: env=dev,owner=you).",
    )
    parser.add_argument(
        "--lifecycle-expire-noncurrent-days",
        type=int,
        default=0,
        help="Expire noncurrent object versions after N days (0=disabled).",
    )
    parser.add_argument(
        "--ca-truststore-file",
        type=str,
        default="certificates/truststore.pem",
        help="Path to the CA truststore file to upload (default: certificates/truststore.pem).",
    )
    parser.add_argument(
        "--transparency-enabled",
        action="store_true",
        help="Enable Certificate Transparency logging.",
    )
    parser.add_argument(
        "--key-algorithm",
        default="RSA_2048",
        choices=["RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1"],
        help="Key algorithm (default: RSA_2048).",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point for the mTLS manager tool."""
    args = parse_args()

    try:
        # 1. Create the trust store bucket and uploade the CA truststore
        bucket_manager = CertificateBucketManager(
            bucket=args.bucket,
            region=args.region_name,
            kms_key_id=args.kms_key_id,
            tags=args.tags,
            lifecycle_expire_noncurrent_days=args.lifecycle_expire_noncurrent_days,
            ca_truststore_file=args.ca_truststore_file,
        )
        bucket_manager.deploy()
        bucket_arn = bucket_manager.bucket_arn

        # 2. Request the ACM certificate and upload the API domain certificate
        cert_manager = ACMCertManager(
            domain=args.domain,
            region=args.region_name,
            sans=ACMCertManager.parse_sans(args.sans),
            transparency_enabled=args.transparency_enabled,
            key_algorithm=args.key_algorithm,
            tags=ACMCertManager.parse_tags(args.tags),
        )
        cert_arn = cert_manager.deploy()

        # 3. Create a Custom Domain in API Gateway and turn on mTLS
        cert_path = Path(args.ca_truststore_file)
        s3_key = f"certificates/{cert_path.name}"
        version = bucket_manager.get_latest_certificate_version(s3_key)
        if version is None:
            raise ValueError(
                f"Failed to get the latest certificate version for {s3_key}"
            )
        truststore_uri = f"{bucket_arn}/{s3_key}"
        api_domain_manager = APIDomainManager(
            domain=args.domain,
            cert_arn=cert_arn,
            truststore_uri=truststore_uri,
            truststore_version=version,
            region=args.region_name,
        )
        api_domain_manager.deploy()

        # 4. Create an API mapping to bind this domain to the API/stage
        api_mapping_manager = APIMappingManager(
            domain_name=args.domain,
            api_name="calendar_mcp",
            stage="prod",
            base_path=None,
        )
        api_mapping_id = api_mapping_manager.upsert_api_mapping()
        logger.info(f"API mapping created: {api_mapping_id}")

        # 5. Update AWS Parameter Store with the custom domain URL
        ssm_client = boto3.client("ssm", region_name=args.region_name)
        parameter_name = "/apps/prod/calendar/calendar_mcp_url"
        parameter_value = f"https://{args.domain}"

        try:
            ssm_client.put_parameter(
                Name=parameter_name,
                Value=parameter_value,
                Type="String",
                Overwrite=True,
                Description="Calendar MCP API URL with mTLS custom domain",
            )
            logger.info(
                f"Updated Parameter Store: {parameter_name} = {parameter_value}"
            )
        except ClientError as e:
            logger.error(f"Failed to update Parameter Store: {e}")
            raise

        # 6. Disable the default execute-api endpoint

    except Exception as e:
        logger.error(f"Failed to deploy mTLS infrastructure: {e}")
        raise


if __name__ == "__main__":
    main()
