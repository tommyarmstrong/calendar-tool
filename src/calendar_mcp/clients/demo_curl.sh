#!/usr/bin/env bash
set -e
TOKEN=${MCP_BEARER_TOKEN:-dev-secret}
BASE=${BASE_URL:-http://localhost:8000}

echo "List tools:"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/mcp/tools" | jq

echo "Freebusy sample:"
curl -s -X POST "$BASE/mcp/tools/call" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "calendar.freebusy",
    "arguments": {
      "window_start": "2025-10-07T08:00:00+01:00",
      "window_end":   "2025-10-07T18:00:00+01:00"
    }
  }' | jq
