#!/usr/bin/env python3
"""
Create or update an API Gateway v2 HTTP API with routes that invoke Lambda functions.

CLI usage examples
------------------
python create_http_api.py \
  --name calendar-agent-api \
  --route "GET:/health=calendar_agent" \
  --region us-east-1

python create_http_api.py \
  --name my-http-api \
  --route "GET:/health=calendar_agent" \
  --route "POST:/events=calendar_agent" \
  --stage-name prod

python create_http_api.py \
  --name my-http-api \
  --routes-file routes.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError


@dataclass
class RouteSpec:
    method: str
    path: str
    lambda_ref: str  # name or ARN


# ----------------------
# Argument parsing
# ----------------------


def parse_route_arg(s: str) -> RouteSpec:
    """Parse a --route arg of the form 'GET:/path=LambdaNameOrArn'."""
    try:
        lhs, lambda_ref = s.split("=", 1)
        method, path = lhs.split(":", 1)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid --route format: '{s}'. Expected 'METHOD:/path=LambdaNameOrArn'"
        ) from None
    method = method.strip().upper()
    path = path.strip() or "/"
    if not path.startswith("/"):
        raise argparse.ArgumentTypeError(f"Route path must start with '/': '{path}'")
    return RouteSpec(method=method, path=path, lambda_ref=lambda_ref.strip())


def load_routes_file(path: str) -> list[RouteSpec]:
    with open(path) as f:
        data = json.load(f)
    specs: list[RouteSpec] = []
    for item in data:
        specs.append(
            RouteSpec(
                method=str(item["method"]).upper(),
                path=str(item["path"]),
                lambda_ref=str(item["lambda"]),
            )
        )
    return specs


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Create/Update an API Gateway v2 HTTP API with Lambda routes."
    )
    ap.add_argument("--name", required=True, help="HTTP API name")
    ap.add_argument(
        "--route",
        action="append",
        default=[],
        type=parse_route_arg,
        help="Route spec 'METHOD:/path=LambdaNameOrArn'. Can be repeated.",
    )
    ap.add_argument("--routes-file", help="JSON file: array of {method,path,lambda}")
    ap.add_argument("--stage-name", default="prod", help="Stage name (default: prod)")
    ap.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    return ap.parse_args()


# ----------------------
# AWS helpers
# ----------------------


def get_account_id() -> str:
    sts = boto3.client("sts")
    return str(sts.get_caller_identity()["Account"])


def ensure_http_api(api: Any, name: str) -> dict[str, Any]:
    # Try to find existing API by name (best-effort)
    for page in api.get_paginator("get_apis").paginate():
        for a in page.get("Items", []):
            if a.get("Name") == name and a.get("ProtocolType") == "HTTP":
                return dict(a)
    # Create new HTTP API
    resp = api.create_api(Name=name, ProtocolType="HTTP")
    return dict(resp)


def get_lambda_arn(lambda_client: Any, ref: str) -> str:
    if ref.startswith("arn:aws:lambda:"):
        return ref
    # Resolve by name
    resp = lambda_client.get_function(FunctionName=ref)
    return str(resp["Configuration"]["FunctionArn"])


def ensure_stage(
    api: Any, api_id: str, stage_name: str, auto_deploy: bool = True
) -> dict[str, Any]:
    try:
        existing = api.get_stage(ApiId=api_id, StageName=stage_name)
        if existing.get("AutoDeploy") != auto_deploy:
            api.update_stage(ApiId=api_id, StageName=stage_name, AutoDeploy=auto_deploy)
            existing = api.get_stage(ApiId=api_id, StageName=stage_name)
        return dict(existing)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "NotFoundException":
            return dict(
                api.create_stage(ApiId=api_id, StageName=stage_name, AutoDeploy=auto_deploy)
            )
        raise


def find_existing_integration(api: Any, api_id: str, lambda_arn: str) -> str | None:
    """Try to find an existing Lambda proxy integration pointing at lambda_arn."""
    paginator = api.get_paginator("get_integrations")
    for page in paginator.paginate(ApiId=api_id):
        for integ in page.get("Items", []):
            if integ.get("IntegrationType") == "AWS_PROXY" and integ.get(
                "IntegrationUri", ""
            ).endswith(lambda_arn):
                return str(integ.get("IntegrationId", ""))
    return None


def ensure_integration(api: Any, api_id: str, region: str, lambda_arn: str) -> str:
    """
    Create (or reuse) an AWS_PROXY integration to the Lambda.
    IntegrationUri format:
      arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{lambdaArn}/invocations
    """
    existing = find_existing_integration(api, api_id, lambda_arn)
    if existing:
        return existing

    uri = f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations"
    resp = api.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",  # required but ignored for Lambda proxy
        IntegrationUri=uri,
        PayloadFormatVersion="2.0",
        TimeoutInMillis=29000,
    )
    return str(resp["IntegrationId"])


def route_key(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def ensure_route(
    api: Any, api_id: str, method: str, path: str, integration_id: str
) -> dict[str, Any]:
    rk = route_key(method, path)
    paginator = api.get_paginator("get_routes")
    for page in paginator.paginate(ApiId=api_id):
        for r in page.get("Items", []):
            if r.get("RouteKey") == rk:
                desired = f"integrations/{integration_id}"
                if r.get("Target") != desired:
                    api.update_route(ApiId=api_id, RouteId=r["RouteId"], Target=desired)
                    return dict(api.get_route(ApiId=api_id, RouteId=r["RouteId"]))
                return dict(r)
    return dict(
        api.create_route(ApiId=api_id, RouteKey=rk, Target=f"integrations/{integration_id}")
    )


def ensure_lambda_permission_for_apigw(
    lambda_client: Any,
    lambda_arn: str,
    api_id: str,
    region: str,
    account_id: str,
    method: str,
    path: str,
) -> None:
    """
    Add lambda:AddPermission so API Gateway can invoke the function.
    Uses deterministic StatementId per api+method+path.
    """
    path_nolead = path[1:] if path.startswith("/") else path
    source_arn = (
        f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/{method.upper()}/{path_nolead}"
    )

    sid_hash = hashlib.sha256(f"{api_id}:{method}:{path}".encode()).hexdigest()[:16]
    statement_id = f"apigw-{api_id}-{sid_hash}"

    # Check if permission already exists
    try:
        pol = lambda_client.get_policy(FunctionName=lambda_arn)
        doc = json.loads(pol["Policy"])
        for stmt in doc.get("Statement", []):
            if stmt.get("Sid") == statement_id:
                return  # already present
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") not in (
            "ResourceNotFoundException",
            "ResourceNotFound",
        ):
            raise

    try:
        lambda_client.add_permission(
            FunctionName=lambda_arn,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


# ----------------------
# Library-friendly entry
# ----------------------


def process_http_gateways(
    *,
    name: str,
    routes: list[RouteSpec] | None = None,
    routes_file: str | None = None,
    stage_name: str = "prod",
    region: str = "us-east-1",
) -> dict[str, Any]:
    """
    Create/update an HTTP API and wire routes to Lambda functions.

    Returns a dict:
      {
        "api_id": "...",
        "stage_name": "...",
        "base_url": "https://{api_id}.execute-api.{region}.amazonaws.com/{stage_name}",
        "routes": [{"method": "...", "path": "...", "lambda_arn": "..."}]
      }
    """
    routes = routes or []
    if routes_file:
        routes.extend(load_routes_file(routes_file))

    if not routes:
        raise ValueError("At least one route must be provided (via 'routes' or 'routes_file').")

    # Normalize/validate methods
    for r in routes:
        r.method = r.method.upper()
        if r.method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}:
            print(f"WARNING: Unusual HTTP method '{r.method}'. Proceeding anyway.", file=sys.stderr)

    account_id = get_account_id()
    print(f"Using AWS account: {account_id}, region: {region}")

    api = boto3.client("apigatewayv2", region_name=region)
    lam = boto3.client("lambda", region_name=region)

    # 1) Ensure API
    api_info = ensure_http_api(api, name)
    api_id = api_info["ApiId"]
    print(f"API: {api_info['Name']}  (id: {api_id})")

    # 2) Ensure stage
    stage = ensure_stage(api, api_id, stage_name, auto_deploy=True)
    print(f"Stage: {stage['StageName']} (AutoDeploy={stage.get('AutoDeploy')})")

    # 3) Ensure integrations/routes/permissions
    ensured: list[dict[str, Any]] = []
    for r in routes:
        lambda_arn = get_lambda_arn(lam, r.lambda_ref)
        integration_id = ensure_integration(api, api_id, region, lambda_arn)
        route = ensure_route(api, api_id, r.method, r.path, integration_id)
        ensure_lambda_permission_for_apigw(
            lam, lambda_arn, api_id, region, account_id, r.method, r.path
        )
        ensured.append({"method": r.method, "path": r.path, "lambda_arn": lambda_arn})
        print(f"✔ Route ensured: {route['RouteKey']} → integrations/{integration_id}")

    base_url = f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage_name}"
    print("\nInvoke URLs:")
    for r in routes:
        print(f"  {r.method} {base_url}{r.path}")

    return {
        "api_id": api_id,
        "stage_name": stage_name,
        "base_url": base_url,
        "routes": ensured,
    }


# ----------------------
# CLI entry
# ----------------------


def main() -> int:
    args = parse_args()
    try:
        process_http_gateways(
            name=args.name,
            routes=list(args.route),
            routes_file=args.routes_file,
            stage_name=args.stage_name,
            region=args.region,
        )
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
