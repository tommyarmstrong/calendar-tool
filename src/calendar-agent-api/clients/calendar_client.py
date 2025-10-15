#!/usr/bin/env python3
"""
Calendar Agent Client

A command-line client for interacting with the Calendar Agent API.
Takes a message and bearer token as arguments and handles the HTTP request.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from infrastructure.platform_manager import create_logger, get_parameters
from services.cache_service import RedisCache

X_CLIENT_ID = "dev-test-client-v1"
CLIENT_TIMEOUT = 60  # Seconds

# Secrets are encrypted in the AWS Parameter Store
secrets = get_parameters(
    ["redis_password"],
    "/apps/prod/secrets/",
    decrypt=True,
)

# Infrastructure parameters are not encrypted in the AWS Parameter Store
infra_params = get_parameters(
    ["redis_host", "redis_port"],
    "/apps/prod/infra/",
)

REDIS_PASSWORD = secrets["redis_password"]
REDIS_HOST = infra_params["redis_host"]
REDIS_PORT = infra_params["redis_port"]

logger = create_logger(logger_name="calendar-client", log_level="INFO")
logger.info("Starting Calendar Client")


def parse_response(response_message: dict[str, Any]) -> None:
    """
    Parse the free/busy response from the Calendar Agent API.
    """
    if response_message.get("kind") == "calendar#freeBusy":
        start_timestamp = pretty_datetime(response_message.get("timeMin", ""))
        end_timestamp = pretty_datetime(response_message.get("timeMax", ""))
        logger.info(f"In the time window: {start_timestamp} - {end_timestamp}")
        logger.info("You have events scheduled in the following spots...")
        calendars = response_message.get('calendars', {})
        for calendar, busy in calendars.items():
            logger.info(f">> Calendar: {calendar.capitalize()} : {busy.get('busy', [])}")

    elif response_message.get("error"):
        code = response_message.get("error", {}).get("code")
        message = response_message.get("error", {}).get("message")
        logger.error(f"{code} - {message}")
        if code.strip() == "not_authenticated" and message.strip() == "Google not linked":
            logger.info("Link your Google account to the MCP service.")
        sys.exit(1)

    else:
        logger.info(f"Response: {json.dumps(response_message, indent=2)}")
    return None


def pretty_datetime(
    iso_utc: str, tz: str = "Europe/London", fmt: str = "%a %d %b %Y, %H:%M (%Z)"
) -> str:
    """
    Convert an ISO 8601 UTC datetime string (e.g., '2025-10-13T00:00:00.000Z')
    into a nicely formatted local time string.

    Args:
        iso_utc: ISO 8601 string ending with 'Z' (UTC).
        tz: IANA timezone for output (default 'Europe/London').
        fmt: strftime format for output (default 'Mon 13 Oct 2025, 01:00 (BST)').

    Returns:
        Formatted datetime string in the target timezone.
    """
    # Make it RFC 3339-friendly for fromisoformat
    dt_utc = datetime.fromisoformat(iso_utc.replace("Z", "+00:00"))
    dt_local = dt_utc.astimezone(ZoneInfo(tz))
    return dt_local.strftime(fmt)


def make_request(
    message: str,
    bearer_token: str,
    url: str = "http://127.0.0.1",
    port: int | None = None,
    endpoint: str = "/agents/calendar",
) -> tuple[int, dict[str, Any]]:
    """
    Make a request to the Calendar Agent API.

    Args:
        message: The message to send to the agent
        bearer_token: The OAuth bearer token for authentication
        url: The base URL of the agent server
        port: The port of the agent server
        endpoint: The API endpoint path

    Returns:
        Dictionary containing the response data

    Raises:
        requests.RequestException: If the HTTP request fails
    """
    # Construct the full URL
    if port is not None:
        full_url = f"{url}:{port}{endpoint}"
    else:
        full_url = f"{url}{endpoint}"

    # Prepare headers
    headers = {
        "Content-Type": "application/json",
        "x-client-id": X_CLIENT_ID,
        "Authorization": f"Bearer {bearer_token}",
    }

    # Prepare request body
    payload = {"message": message}

    try:
        # Make the request
        response = requests.post(
            full_url,
            headers=headers,
            json=payload,
            timeout=10,
        )
        # Check for HTTP errors
        response.raise_for_status()

        # Parse and return the JSON response
        return (response.status_code, dict(response.json()))

    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        raise


def poll_for_status(status_key: str, timeout: int = CLIENT_TIMEOUT) -> None:
    """
    Poll Redis for status updates keyed by `status_key`.

    Waits up to `timeout` seconds for a 200 response with a final message.
    The polling starts fast and backs off over time, expecting completion within ~10s.

    Args:
        status_key (str): Redis key to poll for status updates.
        timeout (int, optional): Maximum time to wait in seconds. Defaults to CLIENT_TIMEOUT.

    Returns:
        None
    """
    assert REDIS_HOST is not None and REDIS_PORT is not None and REDIS_PASSWORD is not None

    cache = RedisCache(REDIS_HOST, int(REDIS_PORT), REDIS_PASSWORD)
    start_time = time.time()

    # Backoff configuration
    base_delay = 0.25  # start delay in seconds
    max_delay = 2.0  # max delay between polls
    multiplier = 1.5  # how fast we back off

    delay = base_delay
    attempt = 0

    while True:
        elapsed = time.time() - start_time
        if elapsed >= timeout:
            logger.error(f"Client timeout after {round(elapsed, 2)} seconds")
            return

        result = cache.get_json(status_key)
        if result:
            status_code = result.get("status_code")
            message = result.get("message")
            # assert message is dict[str, Any], "Message is not a dictionary in expected format"

            if status_code == 200 and isinstance(message, dict):
                parse_response(message)  # type: ignore
                logger.info(f"Response received in {round(elapsed, 2)} seconds")
                return

            elif status_code == 202:
                time.sleep(delay)
                attempt += 1
                delay = min(delay * multiplier, max_delay)
                continue

            else:
                logger.error(f"{status_code} - {message}")
                return

        time.sleep(delay)
        attempt += 1
        delay = min(delay * multiplier, max_delay)


def get_ngrok_url() -> str | None:
    """
    Get the public ngrok URL for local development.

    Returns:
        str or None: The public ngrok URL if available, else None.
    """
    try:
        response = requests.get("http://localhost:4040/api/tunnels")
        response.raise_for_status()
        tunnels = response.json().get("tunnels", [])

        # Prefer HTTPS tunnels
        for tunnel in tunnels:
            if tunnel["proto"] == "https":
                return str(tunnel["public_url"])

        return str(tunnels[0]["public_url"]) if tunnels else None
    except requests.RequestException as e:
        logger.error("Error fetching ngrok URL:", e)
        return None


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Calendar Agent Client - Send messages to the Calendar Agent API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "What meetings do I have today?" ya29.a0AfH6SMC...
  %(prog)s "Create a meeting tomorrow at 2pm" ya29.a0AfH6SMC... --url http://localhost --port 8080
  %(prog)s "Show my calendar" ya29.a0AfH6SMC... --url https://api.example.com --port 443
        """,
    )

    # Required arguments
    parser.add_argument(
        "message",
        help="The message to send to the calendar agent",
    )

    parser.add_argument(
        "--token",
        help="The OAuth bearer token for authentication",
    )

    # Optional arguments
    parser.add_argument(
        "--url",
        default="http://127.0.0.1",
        help="Base URL of the agent server (default: http://127.0.0.1)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port of the agent server (default: no port)",
    )

    parser.add_argument(
        "--endpoint",
        default="/agents/calendar",
        help="API endpoint path (default: /agents/calendar)",
    )

    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print the JSON response",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show verbose output including request details",
    )

    parser.add_argument(
        "--ngrok",
        action="store_true",
        help="Use ngrok for local development",
    )

    args = parser.parse_args()

    # Use ngrok for local development
    if args.ngrok:
        args.url = get_ngrok_url()
        if args.url is None:
            logger.error("Error: No ngrok URL found.")
            sys.exit(1)

    # Show request details if verbose
    if args.verbose:
        if args.port is not None:
            logger.info(f"Making request to: {args.url}:{args.port}{args.endpoint}")
        else:
            logger.info(f"Making request to: {args.url}{args.endpoint}")
        logger.info(f"Message: {args.message}")
        logger.info(f"Bearer token: {args.token[:5]}**********\n")

    return args


def main() -> None:
    """Main function to handle command line arguments and make the request."""
    args = parse_arguments()

    try:
        # Make the request
        status_code, response = make_request(
            message=args.message,
            bearer_token=args.token,
            url=args.url,
            port=args.port,
            endpoint=args.endpoint,
        )

        if status_code < 200 or status_code >= 300:
            logger.error(f"{status_code} {response['message']}")
            sys.exit(1)

        if status_code == 202:
            logger.info(response['message'])
            logger.info(response['status_update_key'])
            logger.info("Polling for status update...")
            poll_for_status(response['status_update_key'])

    except requests.exceptions.RequestException as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing response: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.error("\nRequest cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
