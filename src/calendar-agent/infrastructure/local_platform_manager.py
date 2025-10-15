import importlib
import logging
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def create_logger(
    log_level: str = "INFO",
    logger_name: str = "calendar-agent",
    logs_dir: str | Path = "logs",
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


""" Simulated Lambda Invocation (using threading) """


@contextmanager
def temporarily_in_sys_path(*paths: Path) -> Iterator[None]:
    """
    Temporarily insert paths into sys.path.
    """
    original_sys_path = sys.path.copy()
    for path in paths:
        path_str = str(path.resolve())
        if path_str not in sys.path:
            sys.path.insert(0, path_str)
    try:
        yield
    finally:
        sys.path = original_sys_path


@contextmanager
def temporarily_change_dir(path: Path) -> Iterator[None]:
    """
    Temporarily change the current working directory.
    """
    original_cwd = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original_cwd)


def invoke_lambda(
    event: dict[str, Any],
    function_name: str,
    lambda_handler: str = "lambda_handler",
    lambda_handler_filename: str = "handler.py",
) -> None:
    """
    Simulate an AWS Lambda function invocation by dynamically importing the specified
    module and running its handler function in a background thread.

    Args:
        event (dict[str, Any]): The event dictionary to pass to the handler.
        function_name (str): The name of the Python module containing the handler.
        lambda_handler (str): The handler function name within the module. Defaults to
            'lambda_handler'.
    """
    logger = create_logger(logger_name="calendar-agent", log_level="INFO")
    logger.info(f"Invoking lambda function {function_name} with handler {lambda_handler}")

    project_root = Path(__file__).resolve().parent.parent.parent
    module_dir = project_root / "src" / function_name
    module_name = function_name + "." + lambda_handler_filename.rsplit(".", 1)[0]

    with temporarily_in_sys_path(project_root, module_dir):
        with temporarily_change_dir(module_dir):
            try:
                module = importlib.import_module(module_name)
                handler = getattr(module, lambda_handler)
                logger.debug(f"Successfully imported {function_name}.{lambda_handler}")
            except (ModuleNotFoundError, AttributeError) as e:
                raise ImportError(
                    f"Failed to import {lambda_handler} from {function_name}: {e}"
                ) from e

    def thread_wrapper() -> None:
        try:
            logger.debug(f"Thread {module_name}.{lambda_handler} starting execution")
            handler(event, None)
            logger.debug(f"Thread {module_name}.{lambda_handler} completed successfully")
        except Exception as e:
            logger.exception(f"Thread {module_name}.{lambda_handler} failed: {e}")

    thread = threading.Thread(target=thread_wrapper, daemon=True, name=f"{function_name}_handler")
    thread.start()
    logger.debug(f"Started thread for {module_name}.{lambda_handler} (thread_id: {thread.ident})")
