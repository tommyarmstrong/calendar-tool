#!/usr/bin/env python3
"""
Create or update an API Gateway v2 (HTTP API) custom domain with mTLS.

Equivalent to:
aws apigatewayv2 create-domain-name \
  --domain-name "$DOMAIN" \
  --domain-name-configurations "CertificateArn=$ACM_CERT_ARN,EndpointType=REGIONAL,SecurityPolicy=TLS_1_2" \
  --mutual-tls-authentication "TruststoreUri=$TRUSTSTORE_URI,TruststoreVersion=$TRUSTSTORE_VERSION"

Usage:
  python create_apigwv2_domain_mtls.py \
    --domain mcp.example.com \
    --cert-arn arn:aws:acm:eu-west-2:123456789012:certificate/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
    --truststore-uri s3://my-mtls-truststore/truststore.pem \
    --truststore-version <s3-object-version-id> \
    [--region eu-west-2]
"""

import argparse
import re
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError


def validate_s3_uri(uri: str) -> None:
    if not re.match(r"^s3://[^/]+/.+$", uri):
        raise ValueError("TRUSTSTORE_URI must be like s3://bucket/key.pem")


def upsert_domain(
    client: Any,
    domain: str,
    cert_arn: str,
    truststore_uri: str,
    truststore_version: str,
) -> tuple[str, str | None, dict[str, Any]]:
    cfg = {
        "CertificateArn": cert_arn,
        "EndpointType": "REGIONAL",
        "SecurityPolicy": "TLS_1_2",
    }
    mtls = {
        "TruststoreUri": truststore_uri,
        "TruststoreVersion": truststore_version,
    }

    # Try to see if domain already exists
    try:
        client.get_domain_name(DomainName=domain)
        # Update path: only fields that can change (mtls and cert)
        resp = client.update_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[cfg],
            MutualTlsAuthentication=mtls,
        )
        action = "updated"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "NotFoundException":
            resp = client.create_domain_name(
                DomainName=domain,
                DomainNameConfigurations=[cfg],
                MutualTlsAuthentication=mtls,
            )
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create/Update API Gateway v2 custom domain with mTLS"
    )
    parser.add_argument(
        "--region", default="us-east-1", help="AWS region (default: us-east-1)"
    )
    parser.add_argument(
        "--domain", required=True, help="Custom domain name, e.g., mcp.example.com"
    )
    parser.add_argument(
        "--cert-arn", required=True, help="ACM (regional) certificate ARN"
    )
    parser.add_argument(
        "--truststore-uri",
        required=True,
        help="S3 URI to PEM truststore, e.g., s3://bucket/truststore.pem",
    )
    parser.add_argument(
        "--truststore-version",
        required=True,
        help="S3 object version ID for the truststore",
    )
    args = parser.parse_args()

    try:
        validate_s3_uri(args.truststore_uri)
        client: Any = boto3.client("apigatewayv2", region_name=args.region)

        action, agw_domain, resp = upsert_domain(
            client=client,
            domain=args.domain,
            cert_arn=args.cert_arn,
            truststore_uri=args.truststore_uri,
            truststore_version=args.truststore_version,
        )

        print(f"[OK] Custom domain {action}: {args.domain}")
        if agw_domain:
            print(f"[INFO] Point your DNS CNAME to: {agw_domain}")
        else:
            print(
                "[WARN] Could not determine ApiGatewayDomainName from response. Full response follows:"
            )
            print(resp)

        print("\nNext steps:")
        print("  1) Create an API mapping to bind this domain to your API/stage:")
        print(
            "     aws apigatewayv2 create-api-mapping --domain-name {0} --api-id <API_ID> --stage $default --region {1}".format(
                args.domain, args.region
            )
        )
        print(
            "  2) In your DNS provider, create a CNAME from {0} to the ApiGateway domain above.".format(
                args.domain
            )
        )
        print(
            "  3) Call your API via https://{0}/ ... (mTLS enforced only on the custom domain).".format(
                args.domain
            )
        )

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
