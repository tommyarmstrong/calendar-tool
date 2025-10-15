import logging
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import import_module, invalidate_caches
from pathlib import Path
from typing import Any


def create_logger(
    log_level: str = "INFO",
    logger_name: str = "calendar-agent-api",
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
    lambda_handler: str = "agent_lambda_handler",
    lambda_handler_filename: str = "calendar_agent_handler.py",
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
    logger = create_logger(logger_name="calendar-agent-api", log_level="INFO")
    logger.info(
        f"Invoking lambda function {function_name} "
        + f"with handler {lambda_handler_filename}.{lambda_handler}"
    )

    # Go up to parent directory and look for the function_name project
    current_project_root = Path(__file__).resolve().parent.parent.parent
    parent_dir = current_project_root.parent
    logger.info(f"Current project root: {current_project_root}")
    logger.info(f"Searching parent: {parent_dir}")

    # Try to find the project directory by replacing - with _ in function_name
    function_name_with_underscores = function_name.replace("-", "_")
    function_name_with_hyphens = function_name.replace("_", "-")

    # Look for directories matching function_name, function_name_with_underscores,
    # or function_name_with_hyphens
    potential_dirs = [
        current_project_root / function_name,
        current_project_root / function_name_with_underscores,
        current_project_root / function_name_with_hyphens,
        parent_dir / function_name,
        parent_dir / function_name_with_underscores,
        parent_dir / function_name_with_hyphens,
    ]

    project_root = None
    for potential_dir in potential_dirs:
        if potential_dir.exists() and potential_dir.is_dir():
            project_root = potential_dir
            logger.debug(f"Found function directory: {project_root}")
            break

    if project_root is None:
        raise ImportError(
            f"Could not find project directory for function '{function_name}'. "
            + f"Looked in: {[str(d) for d in potential_dirs]}"
        )

    module_dir = project_root
    module_name = lambda_handler_filename.rsplit(".", 1)[0]

    logger.debug(f"Module directory: {module_dir}")
    logger.debug(f"Module name: {module_name}")
    logger.debug(f"Handler function: {lambda_handler}")

    # Make sure the sibling project's src wins (order matters: put module_dir first)
    with temporarily_in_sys_path(module_dir, project_root):
        with temporarily_change_dir(module_dir):
            try:
                # If another 'services' package was already imported (e.g., from your API repo),
                # remove it so our sibling project's 'services' can be imported instead.
                sys.modules.pop("infrastructure", None)
                sys.modules.pop("services", None)
                invalidate_caches()

                module = import_module(module_name)
                handler = getattr(module, lambda_handler)
                logger.debug(f"Successfully imported {function_name}.{lambda_handler}")
            except (ModuleNotFoundError, AttributeError) as e:
                raise ImportError(
                    f"Failed to import {lambda_handler} from {function_name}: {e}"
                ) from e

    def thread_wrapper() -> None:
        try:
            # Replicate import context inside the thread for any lazy imports.
            # (Threads inherit sys.modules, but sys.path order can still matter for late imports.)
            paths_to_prepend = [str(module_dir), str(project_root)]
            for p in paths_to_prepend:
                if p not in sys.path:
                    sys.path.insert(0, p)

            # Also ensure any stale 'services' binding is cleared in this thread.
            sys.modules.pop("services", None)
            invalidate_caches()

            logger.debug(f"Thread {module_name}.{lambda_handler} starting execution")
            handler(event, None)
            logger.debug(f"Thread {module_name}.{lambda_handler} completed successfully")
        except Exception as e:
            logger.exception(f"Thread {module_name}.{lambda_handler} failed: {e}")

    thread = threading.Thread(target=thread_wrapper, daemon=True, name=f"{function_name}_handler")
    thread.start()
    logger.debug(f"Started thread for {module_name}.{lambda_handler} (thread_id: {thread.ident})")
