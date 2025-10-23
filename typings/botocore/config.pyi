from typing import Any

class Config:
    def __init__(
        self,
        *,
        read_timeout: int | None = None,
        connect_timeout: int | None = None,
        retries: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None: ...
