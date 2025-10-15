import json
import os
from typing import Any

import requests

BASE = os.getenv("CALENDAR_MCP_URL", "http://localhost:8000")
TOKEN = os.getenv("CALENDAR_MCP_TOKEN", "dev-test-token")


def call_tool(name: str, arguments: dict[str, str]) -> Any:
    r = requests.post(
        f"{BASE}/mcp/tools/call",
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        json={"name": name, "arguments": arguments},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    print(
        json.dumps(
            call_tool(
                "calendar.freebusy",
                {
                    "window_start": "2025-10-08T08:00:00+01:00",
                    "window_end": "2025-10-08T18:00:00+01:00",
                },
            ),
            indent=2,
        )
    )
