"""Type stubs for botocore.exceptions."""

from typing import Any

class ClientError(Exception):
    response: dict[str, Any]
