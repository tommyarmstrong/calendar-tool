def manifest(base_url: str) -> dict[str, str | dict[str, str]]:
    return {
        "name": "calendar-mcp",
        "version": "0.1.0",
        "description": "MCP server exposing Google Calendar tools",
        "tools_endpoint": f"{base_url}/mcp/tools",
        "schema_endpoint": f"{base_url}/mcp/schemas",
        "auth": {"type": "hmac"},  # HMAC auth: timestamp/nonce/signature headers
    }
