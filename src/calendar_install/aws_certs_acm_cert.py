#!/usr/bin/env python3
"""
Request an ACM (public) certificate with DNS validation and print the required
DNS CNAME records. Optionally wait for issuance.

Usage examples:
  python request_acm_cert.py --region eu-west-2 --domain mcp.example.com
  python request_acm_cert.py --region eu-west-2 --domain mcp.example.com \
      --san api.example.com,*.internal.example.com --disable-ct
  python request_acm_cert.py --region eu-west-2 --domain mcp.example.com --wait --timeout 900
  python request_acm_cert.py --region eu-west-2 --domain mcp.example.com \
      --key-algorithm RSA_2048 --tags env=dev,owner=platform
"""

import argparse
import sys
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError


def parse_sans(sans: str | None) -> list[str]:
    if not sans:
        return []
    return [s.strip() for s in sans.split(",") if s.strip()]


def parse_tags(tag_str: str | None) -> list[dict[str, str]]:
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


def request_certificate(
    acm: Any,
    domain: str,
    sans: list[str],
    transparency_enabled: bool,
    key_algorithm: str,
    tags: list[dict[str, str]],
) -> str:
    """
    Request a public certificate with DNS validation.
    Returns the CertificateArn.
    """
    options = {
        "CertificateTransparencyLoggingPreference": "ENABLED"
        if transparency_enabled
        else "DISABLED"
    }

    params: dict[str, Any] = {
        "DomainName": domain,
        "ValidationMethod": "DNS",
        "Options": options,
        "KeyAlgorithm": key_algorithm,  # e.g., RSA_2048, EC_prime256v1
        "Tags": tags or [],
    }
    if sans:
        params["SubjectAlternativeNames"] = sans

    resp = acm.request_certificate(**params)
    cert_arn: str = resp["CertificateArn"]
    return cert_arn


def get_dns_records_for_validation(acm: Any, cert_arn: str) -> list[dict[str, str]]:
    """
    Returns a list of DNS records you must add:
    [{'Name': '...', 'Type': 'CNAME', 'Value': '...'}, ...]
    """
    desc = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
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


def wait_for_issuance(
    acm: Any, cert_arn: str, timeout_sec: int = 900, poll_sec: int = 10
) -> str:
    """
    Poll ACM until the certificate is ISSUED (or FAILED/timeout).
    Returns the final status.
    """
    start = time.time()
    status = "PENDING_VALIDATION"
    while True:
        desc = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
        status = desc.get("Status", "UNKNOWN")
        if status in ("ISSUED", "FAILED", "REVOKED"):
            return status
        if time.time() - start > timeout_sec:
            return status
        time.sleep(poll_sec)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Request an ACM public certificate with DNS validation."
    )
    p.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (must match where the cert will be used) (default: us-east-1).",
    )
    p.add_argument(
        "--domain",
        required=True,
        help="Primary domain name (e.g., mcp.example.com or *.example.com).",
    )
    p.add_argument("--san", help="Comma-separated Subject Alternative Names.")
    p.add_argument(
        "--disable-ct",
        action="store_true",
        help="Disable Certificate Transparency logging.",
    )
    p.add_argument(
        "--key-algorithm",
        default="RSA_2048",
        choices=["RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1"],
        help="Key algorithm (default: RSA_2048).",
    )
    p.add_argument("--tags", help="Comma-separated tags: key1=val1,key2=val2")
    p.add_argument(
        "--wait",
        action="store_true",
        help="Wait until the certificate is ISSUED (polls ACM).",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Max seconds to wait when --wait is set (default 900).",
    )
    args = p.parse_args()

    session: Any = boto3.Session(region_name=args.region)
    acm: Any = session.client("acm")

    try:
        cert_arn = request_certificate(
            acm=acm,
            domain=args.domain,
            sans=parse_sans(args.san),
            transparency_enabled=not args.disable_ct,
            key_algorithm=args.key_algorithm,
            tags=parse_tags(args.tags),
        )
        print("[OK] Requested certificate:")
        print(f"     ARN: {cert_arn}")
        print()

        # Show DNS records to add for validation
        records = get_dns_records_for_validation(acm, cert_arn)
        if records:
            print(
                "[ACTION REQUIRED] Add the following DNS CNAME record(s) at your DNS provider:"
            )
            for rr in records:
                print(f"  - Name : {rr['Name']}")
                print(f"    Type : {rr['Type']}")
                print(f"    Value: {rr['Value']}")
            print(
                "\nAfter propagating DNS, ACM will validate and issue the cert automatically."
            )
        else:
            print(
                "[INFO] No DNS records returned yet. Re-run describe later to fetch CNAMEs."
            )

        # Optionally wait for issuance
        if args.wait:
            print("\n[WAIT] Waiting for status ISSUED...")
            status = wait_for_issuance(acm, cert_arn, timeout_sec=args.timeout)
            print(f"[STATUS] {status}")
            if status != "ISSUED":
                print(
                    "[HINT] If still pending, ensure the CNAMEs are correct and propagated (TTL)."
                )

    except ClientError as e:
        print(
            f"[ERROR] {e.response.get('Error', {}).get('Code')}: {e.response.get('Error', {}).get('Message')}",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
