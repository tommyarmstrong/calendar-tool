# fast_api_server/google_oauth_server.py
#
# Run the OAuth server with non-mTLS on port 8001:
#
# uvicorn fast_api_server.google_oauth_server:app --reload --port 8001


from __future__ import annotations

import base64
import time
import traceback
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from mcp_handler import lambda_handler


def _lambda_to_fastapi_response(lambda_resp: dict[str, Any]) -> Response:
    """
    Convert an HTTP API v2 Lambda proxy response to a FastAPI Response.
    Expected Lambda response keys (HTTP API v2):
      - statusCode: int
      - headers: dict[str, str] (optional)
      - body: str (JSON/text or base64-encoded data when isBase64Encoded=True)
      - isBase64Encoded: bool (optional)
    """
    status_code = int(lambda_resp.get("statusCode", 200))
    headers: dict[str, Any] = lambda_resp.get("headers", {}) or {}
    headers = {k: str(v) for k, v in headers.items()}

    body = lambda_resp.get("body", "")
    is_b64 = bool(lambda_resp.get("isBase64Encoded", False))

    if is_b64 and isinstance(body, str):
        body_bytes = base64.b64decode(body)
        return Response(content=body_bytes, status_code=status_code, headers=headers)

    if isinstance(body, dict):
        return JSONResponse(content=body, status_code=status_code, headers=headers)

    ctype = headers.get("content-type") or headers.get("Content-Type") or "text/plain"
    return Response(
        content=(body or ""), status_code=status_code, media_type=ctype, headers=headers
    )


def _build_httpapi_v2_event(request: Request, body_bytes: bytes) -> dict[str, Any]:
    """
    Build an AWS API Gateway HTTP API v2 event from FastAPI's Request.
    """
    method = request.method
    path = request.url.path
    raw_query = request.url.query or ""
    http_version = request.scope.get("http_version", "1.1")

    # Body → string or base64 per HTTP API v2
    is_b64 = False
    if body_bytes:
        try:
            body_str = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            body_str = base64.b64encode(body_bytes).decode("ascii")
            is_b64 = True
    else:
        body_str = ""

    headers = {k: v for k, v in request.headers.items()}
    now_ms = int(time.time() * 1000)
    host = headers.get("host", "localhost")
    domain_prefix = host.split(".")[0] if "." in host else host

    return {
        "version": "2.0",
        "routeKey": f"{method} {path}",
        "rawPath": path,
        "rawQueryString": raw_query,
        "headers": headers or None,
        "queryStringParameters": dict(request.query_params) or None,
        "requestContext": {
            "accountId": "000000000000",
            "apiId": "local",
            "domainName": host,
            "domainPrefix": domain_prefix,
            "time": time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(now_ms / 1000)),
            "timeEpoch": now_ms,
            "http": {
                "method": method,
                "path": path,
                "protocol": f"HTTP/{str(http_version).upper()}",
                "sourceIp": request.client.host if request.client else "127.0.0.1",
                "userAgent": headers.get("user-agent", ""),
            },
            "routeKey": f"{method} {path}",
            "stage": "$default",
        },
        "body": body_str,
        "pathParameters": None,
        "stageVariables": None,
        "isBase64Encoded": is_b64,
    }


async def _process_request(request: Request) -> Response:
    try:
        body_bytes = await request.body()
        event = _build_httpapi_v2_event(request, body_bytes)
        lambda_resp = lambda_handler(event, None)
        return _lambda_to_fastapi_response(lambda_resp)
    except Exception as e:
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"error": "BridgeError", "detail": str(e)},
        )


# ===== FastAPI app & routers =====
app = FastAPI(title="Google OAuth Redirect Service")


# --- OAuth flow ---
@app.get("/oauth/start")
async def oauth_start(request: Request) -> Response:
    return await _process_request(request)


@app.get("/oauth/callback")
async def oauth_callback(request: Request) -> Response:
    return await _process_request(request)
