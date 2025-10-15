from typing import Any, Dict, Optional, Union

class Response:
    def __init__(
        self,
        content: Union[str, bytes, None] = None,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        media_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None: ...

class JSONResponse(Response):
    def __init__(
        self,
        content: Any = None,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> None: ...

class PlainTextResponse(Response):
    def __init__(
        self,
        content: str = "",
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> None: ...

class RedirectResponse(Response):
    def __init__(
        self,
        url: str,
        status_code: int = 307,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> None: ...
