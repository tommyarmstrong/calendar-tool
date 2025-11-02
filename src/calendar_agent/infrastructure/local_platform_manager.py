import logging
import os
from pathlib import Path


def create_logger(
    log_level: str = "INFO",
    logger_name: str = "calendar-agent",
    logs_dir: str | Path = "../logs",
) -> logging.Logger:
    """
    Create a logger that outputs to console and optionally to a file.

    Args:
        log_level (str): Logging level (e.g., "INFO", "DEBUG").
        logger_name (str): Name for the logger instance.
        logs_dir (str | Path | None): Directory for log files. If None, uses default based on
            environment.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logs_dir = Path(logs_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, log_level.upper(), logging.DEBUG))
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    if not logger.hasHandlers():  # Prevent handler duplication
        # Console handler (stdio) - always add this
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        try:
            file_handler = logging.FileHandler(logs_dir / logger_name)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception:
            # If file logging fails, just continue with console logging
            pass

    return logger


def get_parameters(
    param_names: list[str] | str,
    base_path: str,
    *,
    decrypt: bool = False,
    region_name: str = "us-east-1",
) -> dict[str, str | None]:
    """
    Retrieve a secret API key from a predefined dictionary or from an environment variable.
    THIS FUNCTION EXISTS AS A TESTING HOOK.

    Args:
        secret_name (str): The name of the secret key to retrieve.

    Returns:
        str: The secret API key as a string. If the key is not found in both the dictionary
            and the environment variables, the function will return None.

    Note:
        Storing API keys in source code is not recommended for production environments.
        RE-IMPLEMENT USING A SECRETS SERVICE.
    """
    if isinstance(param_names, str):
        param_names = [param_names]

    result = {}
    for param_name in param_names:
        # Parameters are stored in the environment variables in uppercase
        # But we want to store them in lowercase in the result dictionary
        param_name = param_name.upper()
        result[param_name.lower()] = os.getenv(param_name)
    return result


def requests_verify_setting() -> bool | str:
    """
    Determine the TLS certificate verification setting for requests.

    Returns the appropriate verification setting for TLS connections:
    - A temporary file path to a CA certificate for localhost development with self-signed certs
    - True for system-trusted certificates (production environments)

    For localhost HTTPS connections with self-signed certificates, this function
    creates a temporary file containing the base64-decoded CA certificate and
    returns its path for use with requests' verify parameter.

    Returns:
        bool | str: Either True for system trust or a file path to a CA certificate

    Raises:
        No exceptions are raised by this function
    """
    paramaters = get_parameters(["calendar_mcp_url"], "_")
    calendar_mcp_url = paramaters.get("calendar_mcp_url")

    assert isinstance(calendar_mcp_url, str) and calendar_mcp_url is not None
    if calendar_mcp_url.startswith("https://localhost"):
        certificate_path = "certificates/truststore.pem"
        if Path(certificate_path).exists():
            return certificate_path

    # Default: use system trust (works with public certs such as from AWS ACM)
    return True
