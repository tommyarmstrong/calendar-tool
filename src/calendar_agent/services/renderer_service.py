import json
import os
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo


def render_prompt() -> str:
    # Get the directory of this file and construct the path to prompts.md
    current_dir = os.path.dirname(os.path.abspath(__file__))
    prompts_path = os.path.join(current_dir, "..", "prompts", "prompts.md")
    with open(prompts_path) as f:
        return f.read()


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


def render_mcp_result(result: dict[str, Any]) -> tuple[str, str]:
    if result.get("kind") == "calendar#freeBusy":
        start_timestamp = pretty_datetime(result.get("timeMin", ""))
        end_timestamp = pretty_datetime(result.get("timeMax", ""))

        result_string = f"In the time window: {start_timestamp} - {end_timestamp}, "
        result_string += "you have events scheduled in the following spots...\n"
        calendars = result.get("calendars", {})
        for calendar, busy in calendars.items():
            result_string += f"Calendar: {calendar.capitalize()} \n"

            events = busy.get("busy", [])
            for event in events:
                start = pretty_datetime(event.get("start"), fmt="%H:%M (%Z)")
                end = pretty_datetime(event.get("end"), fmt="%H:%M (%Z)")
                result_string += f"\t{start} - {end}\n"

        status_code = "200"
        return status_code, result_string

    if result.get("error"):
        code = result.get("error", {}).get("code")
        message = result.get("error", {}).get("message")
        if code.strip() == "not_authenticated" and "Please link your Google account" in message:
            status_code = "401"
            return status_code, message.strip()

    # TODO: Add other cases and then change default to 500
    return "200", json.dumps(result)
