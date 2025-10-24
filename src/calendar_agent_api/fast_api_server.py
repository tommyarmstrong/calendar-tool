# This is a simple test server for the API.
# uvicorn fast_api_server:app --reload --port 9000
from typing import Any

from agent_api_handler import lambda_handler
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response


def _process_response(lambda_resp: dict[str, Any]) -> Response | JSONResponse:
    """Convert an AWS Lambda-style proxy response into a FastAPI Response."""
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

    event = {
        "body": body,
        "isBase64Encoded": False,
        "headers": headers,
        "queryStringParameters": query_params,
        "requestContext": {"http": {"method": method, "path": path}},
    }
    # Response is a Lambda-style response. Set a direct HTTP response in FastAPI
    lambda_response = lambda_handler(event, None)
    return _process_response(lambda_response)


app = FastAPI(title="Calendar Agent")


# --- route to call the Calendar Agent---
@app.post("/agents/calendar")
async def calendar_agent(request: Request) -> Response:
    body = await request.body()
    return _process_request(body, request)


@app.get("/healthz")
def healthz() -> dict[str, bool]:
    return {"ok": True}
