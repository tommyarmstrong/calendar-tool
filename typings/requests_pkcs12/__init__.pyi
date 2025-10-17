from typing import Any

class Pkcs12Adapter:
    def __init__(
        self, pkcs12_data: bytes, pkcs12_password: str, **kwargs: Any
    ) -> None: ...
