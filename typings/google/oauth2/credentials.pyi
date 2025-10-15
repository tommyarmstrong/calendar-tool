from datetime import datetime
from typing import Any, Optional

class Credentials:
    """OAuth 2.0 credentials."""

    def __init__(
        self,
        token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        id_token: Optional[str] = None,
        token_uri: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scopes: Optional[list[str]] = None,
        default_scopes: Optional[list[str]] = None,
        quota_project_id: Optional[str] = None,
        expiry: Optional[datetime] = None,
        rapt_token: Optional[str] = None,
        refresh_handler: Optional[Any] = None,
        enable_reauth_refresh: bool = False,
        granted_scopes: Optional[list[str]] = None,
    ) -> None: ...
    @property
    def expired(self) -> bool: ...
    @property
    def token(self) -> Optional[str]: ...
    @property
    def refresh_token(self) -> Optional[str]: ...
    @property
    def expiry(self) -> Optional[datetime]: ...
    @property
    def scopes(self) -> Optional[list[str]]: ...
    def refresh(self, request: Any) -> None: ...
    def apply(self, headers: dict[str, str]) -> None: ...
    def before_request(
        self, request: Any, method: str, url: str, headers: dict[str, str]
    ) -> None: ...
