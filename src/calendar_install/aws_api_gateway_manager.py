import hashlib
import json
from typing import Any

import boto3
from aws_config_manager import create_logger
from botocore.exceptions import ClientError

logger = create_logger(logger_name="aws_deployment", log_level="INFO")


class APIGatewayManager:
    def __init__(
        self,
        api_name: str,
        api_routes: list[dict[str, str]],
        region_name: str = "us-east-1",
        stage_name: str = "prod",
        account_id: str = "",
    ):
        self.api_name = api_name
        self.api_routes = api_routes
        self.region_name = region_name
        self.stage_name = stage_name
        self.account_id = account_id
        self.api_client = boto3.client("apigatewayv2", region_name=region_name)
        self.lambda_client = boto3.client("lambda", region_name=region_name)

        if not self.api_routes:
            raise ValueError("At least one route must be provided.")

        if not self.account_id:
            raise ValueError("Account ID must be provided.")

        self.checked_routes = self._validate_routes()
        if not self.checked_routes:
            raise ValueError("At least one valid route must be provided.")

        logger.info(
            f"Using AWS account: {self.account_id}, region: {self.region_name}, stage: {self.stage_name}"
        )

    def _validate_routes(self) -> list[dict[str, str]]:
        checked_routes = []
        for route in self.api_routes:
            method = route.get("method")
            path = route["path"]
            lambda_ref = route["lambda_ref"]
            if not method or not path or not lambda_ref:
                logger.error("Method, path, and lambda_ref must be provided.")
                continue

            if method not in {
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS",
                "HEAD",
            }:
                logger.warning(
                    f"WARNING: Unusual HTTP method '{method}'. Proceeding anyway."
                )
            checked_routes.append(route)
        if len(self.checked_routes) != len(self.api_routes):
            logger.warning(
                f"Only {len(self.checked_routes)}/{len(self.api_routes)} routes were validated."
            )

        return checked_routes

    def _ensure_http_api(self) -> dict[str, Any]:
        # Try to find existing API by name (best-effort)
        for page in self.api_client.get_paginator("get_apis").paginate():
            for a in page.get("Items", []):
                if a.get("Name") == self.api_name and a.get("ProtocolType") == "HTTP":
                    return dict(a)
        # Create new HTTP API
        resp = self.api_client.create_api(Name=self.api_name, ProtocolType="HTTP")
        return dict(resp)

    def _ensure_stage(self, api_id: str, auto_deploy: bool = True) -> dict[str, Any]:
        try:
            existing = self.api_client.get_stage(
                ApiId=api_id, StageName=self.stage_name
            )
            if existing.get("AutoDeploy") != auto_deploy:
                self.api_client.update_stage(
                    ApiId=api_id, StageName=self.stage_name, AutoDeploy=auto_deploy
                )
                existing = self.api_client.get_stage(
                    ApiId=api_id, StageName=self.stage_name
                )
            return dict(existing)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NotFoundException":
                return dict(
                    self.api_client.create_stage(
                        ApiId=api_id, StageName=self.stage_name, AutoDeploy=auto_deploy
                    )
                )
            raise

    def _get_lambda_arn(self, function_name: str) -> str:
        if function_name.startswith("arn:aws:lambda:"):
            return function_name
        # Resolve by name
        resp = self.lambda_client.get_function(FunctionName=function_name)
        return str(resp["Configuration"]["FunctionArn"])

    def _find_existing_integration(self, api_id: str, lambda_arn: str) -> str | None:
        """Try to find an existing Lambda proxy integration pointing at lambda_arn."""
        paginator = self.api_client.get_paginator("get_integrations")
        for page in paginator.paginate(ApiId=api_id):
            for integ in page.get("Items", []):
                if integ.get("IntegrationType") == "AWS_PROXY" and integ.get(
                    "IntegrationUri", ""
                ).endswith(lambda_arn):
                    return str(integ.get("IntegrationId", ""))
        return None

    def _ensure_integration(self, api_id: str, lambda_arn: str) -> str:
        """
        Create (or reuse) an AWS_PROXY integration to the Lambda.
        IntegrationUri format:
        arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{lambdaArn}/invocations
        """
        existing = self._find_existing_integration(api_id, lambda_arn)
        if existing:
            return existing

        uri = f"arn:aws:apigateway:{self.region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations"
        resp = self.api_client.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationMethod="POST",  # required but ignored for Lambda proxy
            IntegrationUri=uri,
            PayloadFormatVersion="2.0",
            TimeoutInMillis=29000,
        )
        return str(resp["IntegrationId"])

    @staticmethod
    def _route_key(method: str, path: str) -> str:
        return f"{method.upper()} {path}"

    def _ensure_route(
        self, api_id: str, method: str, path: str, integration_id: str
    ) -> dict[str, Any]:
        rk = self._route_key(method, path)
        paginator = self.api_client.get_paginator("get_routes")
        for page in paginator.paginate(ApiId=api_id):
            for r in page.get("Items", []):
                if r.get("RouteKey") == rk:
                    desired = f"integrations/{integration_id}"
                    if r.get("Target") != desired:
                        self.api_client.update_route(
                            ApiId=api_id, RouteId=r["RouteId"], Target=desired
                        )
                        return dict(
                            self.api_client.get_route(
                                ApiId=api_id, RouteId=r["RouteId"]
                            )
                        )
                    return dict(r)
        return dict(
            self.api_client.create_route(
                ApiId=api_id, RouteKey=rk, Target=f"integrations/{integration_id}"
            )
        )

    def _ensure_lambda_permission_for_apigw(
        self, lambda_arn: str, api_id: str, method: str, path: str
    ) -> None:
        """
        Add lambda:AddPermission so API Gateway can invoke the function.
        Uses deterministic StatementId per api+method+path.
        """
        path_nolead = path[1:] if path.startswith("/") else path
        source_arn = f"arn:aws:execute-api:{self.region_name}:{self.account_id}:{api_id}/*/{method.upper()}/{path_nolead}"

        sid_hash = hashlib.sha256(f"{api_id}:{method}:{path}".encode()).hexdigest()[:16]
        statement_id = f"apigw-{api_id}-{sid_hash}"

        # Check if permission already exists
        try:
            pol = self.lambda_client.get_policy(FunctionName=lambda_arn)
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
            self.lambda_client.add_permission(
                FunctionName=lambda_arn,
                StatementId=statement_id,
                Action="lambda:InvokeFunction",
                Principal="apigateway.amazonaws.com",
                SourceArn=source_arn,
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "ResourceConflictException":
                raise

    def deploy(self) -> dict[str, str | list[dict[str, str]]]:
        # 1) Ensure API
        api_info = self._ensure_http_api()
        api_id = api_info["ApiId"]
        logger.info(f"API: {api_info['Name']}  (id: {api_id})")

        # 2) Ensure stage
        stage = self._ensure_stage(api_id)
        logger.info(
            f"Stage: {stage['StageName']} (AutoDeploy={stage.get('AutoDeploy')})"
        )

        # 3) Ensure integrations/routes/permissions for each route
        ensured: list[dict[str, Any]] = []
        for r in self.checked_routes:
            lambda_function = r.get("lambda")
            method = r.get("method")
            path = r.get("path")
            if not lambda_function or not method or not path:
                logger.error("Lambda function, method, and path must be provided.")
                continue

            lambda_arn = self._get_lambda_arn(lambda_function)
            integration_id = self._ensure_integration(api_id, lambda_arn)
            route = self._ensure_route(api_id, method, path, integration_id)
            self._ensure_lambda_permission_for_apigw(lambda_arn, api_id, method, path)
            ensured.append({
                "method": r.get("method"),
                "path": r.get("path"),
                "lambda_arn": lambda_arn,
            })
            logger.info(
                f"Route ensured: {route['RouteKey']} → integrations/{integration_id}"
            )

        base_url = f"https://{api_id}.execute-api.{self.region_name}.amazonaws.com/{self.stage_name}"
        logger.info("\nInvoke URLs:")
        for r in self.checked_routes:
            logger.info(f"  {r.get('method')} {base_url}{r.get('path')}")

        return {
            "api_id": api_id,
            "stage_name": self.stage_name,
            "base_url": base_url,
            "routes": ensured,
        }
