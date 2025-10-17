# This is a simple test server for the API.
# Run with: uvicorn fast_api_server.server:app --reload --port 8000
#
# To run with mTLS add the following switches to the uvicorn command:
# --ssl-certfile server.crt --ssl-keyfile server.key --ssl-ca-certs ca.crt --ssl-cert-reqs 2
#
# Where --ssl-cert-reqs 0=CERT_NONE, 1=CERT_OPTIONAL, 2=CERT_REQUIRED


from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response

from auth.google_oauth import finish_auth, start_auth_url
from handler import lambda_handler


def _lambda_to_fastapi_response(lambda_resp: dict[str, Any]) -> Response | JSONResponse:
    """
    Convert an AWS Lambda-style proxy response into a FastAPI Response.

    Args:
        lambda_resp (dict): A dict like:
            {
                "statusCode": int,
                "headers": {"Content-Type": str, ...},
                "body": str,
                "isBase64Encoded": bool
            }

    Returns:
        Response: A FastAPI-compatible Response object.
    """
    status_code = lambda_resp.get("statusCode", 200)
    content_type = lambda_resp.get("headers", {}).get("Content-Type", "text/plain")
    body = lambda_resp.get("body", "")
    is_base64 = lambda_resp.get("isBase64Encoded", False)

    if is_base64:
        import base64

        body = base64.b64decode(body)

    # Handle dict content as JSON
    if isinstance(body, dict):
        return JSONResponse(content=body, status_code=status_code)

    return Response(content=body, status_code=status_code, media_type=content_type)


def _process_request(body: bytes, request: Request) -> Response | JSONResponse:
    """Convert a FastAPI request to a Lambda-style event."""
    headers = request.headers
    query_params = dict(request.query_params)
    path = request.url.path
    method = request.method
    routeKey = f"{method} {path}"

    event = {
        "routeKey": routeKey,
        "raw_path": request.url.path,
        "body": body,
        "isBase64Encoded": False,
        "headers": headers,
        "queryStringParameters": query_params,
        "requestContext": {"routeKey": routeKey, "http": {"method": method, "path": path}},
    }
    # Response is a Lambda-style response. Set a direct HTTP response in FastAPI
    lambda_response = lambda_handler(event, None)
    return _lambda_to_fastapi_response(lambda_response)


app: FastAPI = FastAPI(title="Calendar MCP Service")


# --- MCP Discovery and Tools---
@app.get("/.well-known/mcp/manifest")
async def manifest(request: Request) -> Response:
    body = await request.body()
    return _process_request(body, request)


@app.get("/mcp/schemas")
async def schemas(request: Request) -> Response:
    body = await request.body()
    return _process_request(body, request)


@app.get("/mcp/tools")
async def tools(request: Request) -> Response:
    body = await request.body()
    return _process_request(body, request)


@app.post("/mcp/tools/call")
async def tools_call(request: Request) -> Response:
    body = await request.body()
    return _process_request(body, request)


# --- OAuth flow ---
# TODO: This need to be moved to the procssor.py file.
@app.get("/oauth/start")
def oauth_start() -> RedirectResponse:
    url = start_auth_url()
    return RedirectResponse(url)


# TODO: This need to be moved to the procssor.py file.
@app.get("/oauth/callback")
def oauth_callback(code: str | None = None, error: str | None = None) -> PlainTextResponse:
    if error:
        return PlainTextResponse(f"OAuth error: {error}", status_code=400)
    if not code:
        return PlainTextResponse("Missing code", status_code=400)
    finish_auth(code)
    return PlainTextResponse("Google connected ✅ You can close this tab.")


@app.get("/healthz")
def healthz() -> dict[str, bool]:
    return {"ok": True}
