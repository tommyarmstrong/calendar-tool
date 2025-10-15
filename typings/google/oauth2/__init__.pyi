from typing import Any, Optional
from datetime import datetime

class Credentials:
    """Google OAuth2 Credentials class for authentication."""
    def __init__(
        self,
        token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_uri: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scopes: Optional[list[str]] = None,
        expiry: Optional[datetime] = None,
        **kwargs: Any,
    ) -> None: ...

    token: Optional[str]
    refresh_token: Optional[str]
    token_uri: Optional[str]
    client_id: Optional[str]
    client_secret: Optional[str]
    scopes: Optional[list[str]]
    expiry: Optional[datetime]

    def refresh(self, request: Any) -> None: ...
    def valid(self) -> bool: ...

__all__ = ["Credentials"]
