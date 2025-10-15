from typing import Any, Optional, Tuple

class Flow:
    def __init__(self, **kwargs: Any) -> None: ...

    redirect_uri: Optional[str]

    @classmethod
    def from_client_config(
        cls,
        client_config: dict[str, Any],
        scopes: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> "Flow": ...
    def authorization_url(
        self,
        access_type: str = "online",
        prompt: str = "select_account",
        state: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[str, str]: ...
    def fetch_token(self, code: str, **kwargs: Any) -> None: ...
    @property
    def credentials(self) -> Any: ...
