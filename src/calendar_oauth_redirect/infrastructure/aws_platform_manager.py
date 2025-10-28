#!/usr/bin/env python3
# platform_helpers.py
"""
Helper functions for operations on the AWS platform.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from typing import Any

import boto3

""" AWS Parameter Store """


def _chunk(iterable: Iterable[str], size: int) -> Iterator[list[str]]:
    """
    Chunk an iterable into lists of size `size`.
    Used for SSM get_parameters batching because the API only allows up to 10 names at a time.
    """
    it = iter(iterable)
    while True:
        chunk = list([x for _, x in zip(range(size), it, strict=False)])
        if not chunk:
            break
        yield chunk


def get_parameters(
    param_names: list[str] | str,
    base_path: str,
    *,
    decrypt: bool = False,
    region_name: str = "us-east-1",
) -> dict[str, str | None]:
    """
    Retrieve parameters under `base_path` by leaf name.
    Returns a dict mapping each requested leaf name to its value (or None if missing).
    """
    ssm = boto3.client("ssm", region_name=region_name)

    # Convert single parameter name to list
    if isinstance(param_names, str):
        param_names = [param_names]

    # Normalize base_path (exactly one trailing slash)
    base = base_path.rstrip("/") + "/"

    # Pre-fill with None so missing params are explicit
    result: dict[str, str | None] = {name.lower(): None for name in param_names}

    if not param_names:
        return result

    # Build full paths and keep a reverse map to leaf
    to_fetch = [base + name.lower() for name in param_names]
    leaf_by_full = {base + name.lower(): name.lower() for name in param_names}

    for group in _chunk(to_fetch, 10):  # SSM get_parameters max 10 names
        resp = ssm.get_parameters(Names=group, WithDecryption=decrypt)

        for p in resp.get("Parameters", []):
            full = p["Name"]
            leaf = leaf_by_full.get(full, full)
            if leaf is not None:
                result[leaf] = p["Value"]

    return result


""" AWS CloudWatch """


def create_logger(
    log_level: str = "INFO", logger_name: str = __name__
) -> logging.Logger:
    """
    Create a logger for AWS Lambda that outputs to CloudWatch.

    Requires Python 3.11 or later for the late import of logging.
    For earlier versions, quote the hint:
    create_logger(log_level: str = "INFO", logger_name: str = __name__) -> "logging.Logger"

    Args:
        log_level (str): Logging level (e.g., "INFO", "DEBUG").
        logger_name (str): Name for the logger instance.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(getattr(logging, log_level))

    # Check if the logger already has handlers to avoid duplication
    if not logger.hasHandlers():
        # Create a console handler
        handler = logging.StreamHandler()
        handler.setLevel(getattr(logging, log_level))

        # Create a formatter and set it for the handler
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)

        # Add the handler to the logger
        logger.addHandler(handler)

    return logger


""" AWS Lambda functions """


def invoke_lambda(
    event: dict[str, Any], function_name: str, lambda_handler: str = "lambda_handler"
) -> None:
    """
    Asynchronously invoke an AWS Lambda function by name.

    This function uses boto3 to trigger another Lambda function (fire-and-forget),
    passing in the given event dictionary. It returns immediately without waiting
    for the target function to complete.

    Args:
        event (Dict[str, Any]): The event payload to send to the target Lambda function.
        function_name (str): The name of the Lambda function to invoke (e.g., 'podcast_chat').
        lambda_handler (str, optional): The handler function name in the target Lambda.
        Not used by the API but included for compatibility with local invocations.

    Returns:
        None
    """
    lambda_client = boto3.client("lambda")

    lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="Event",  # async / fire-and-forget
        Payload=json.dumps(event).encode("utf-8"),
    )
