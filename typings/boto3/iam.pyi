from typing import Any

class IAMClient:
    def create_role(
        self,
        RoleName: str,
        AssumeRolePolicyDocument: str,
        Path: str | None = None,
        Description: str | None = None,
        MaxSessionDuration: int | None = None,
        Tags: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]: ...
    def get_role(self, RoleName: str) -> dict[str, Any]: ...
    def attach_role_policy(
        self,
        RoleName: str,
        PolicyArn: str,
    ) -> dict[str, Any]: ...
    def put_role_policy(
        self,
        RoleName: str,
        PolicyName: str,
        PolicyDocument: str,
    ) -> dict[str, Any]: ...
    def list_attached_role_policies(
        self,
        RoleName: str,
        PathPrefix: str | None = None,
        Marker: str | None = None,
        MaxItems: int | None = None,
    ) -> dict[str, Any]: ...
