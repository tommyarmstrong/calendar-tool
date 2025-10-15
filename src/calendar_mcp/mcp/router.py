from typing import Any

from mcp.schemas import LIST
from tools.calendar import create_event, freebusy


def list_tools() -> list[dict[str, Any]]:
    return [
        {"name": v["name"], "description": v["description"], "input_schema": v["input_schema"]}
        for v in LIST.values()
    ]


def call_tool(name: str, args: dict[str, Any]) -> Any:
    if name == "calendar.freebusy":
        calendars = args.get("calendars")
        return freebusy(
            args["window_start"], args["window_end"], [calendars] if calendars else None
        )
    if name == "calendar.create_event":
        attendees = args.get("attendees", [])
        if isinstance(attendees, str):
            attendees = attendees.split(",")
        return create_event(
            title=args.get("title", "MCP Created Event"),
            start=args["start"],
            end=args["end"],
            attendees=attendees,
            description=args.get("description"),
            location=args.get("location"),
            conference=args.get("conference", "false") == "true",
            color_id=args.get("color_id", "1"),
        )
    return {"error": f"unknown_tool:{name}"}
