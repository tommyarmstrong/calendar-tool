from typing import Any

def build(
    serviceName: str,
    version: str,
    credentials: Any = None,
    cache_discovery: bool = True,
    **kwargs: Any,
) -> Any: ...
