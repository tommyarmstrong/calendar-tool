from typing import Any, TypedDict

class GetCallerIdentityResponse(TypedDict):
    UserId: str
    Account: str
    Arn: str

class STSClient:
    def get_caller_identity(self) -> GetCallerIdentityResponse: ...
    def assume_role(
        self,
        RoleArn: str,
        RoleSessionName: str,
        Policy: str | None = None,
        DurationSeconds: int | None = None,
        ExternalId: str | None = None,
        SerialNumber: str | None = None,
        TokenCode: str | None = None,
        SourceIdentity: str | None = None,
        Tags: list[dict[str, str]] | None = None,
        TransitiveTagKeys: list[str] | None = None,
    ) -> dict[str, Any]: ...
