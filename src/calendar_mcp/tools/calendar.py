from __future__ import annotations

import hashlib
from typing import Any

from app.config import get_settings
from auth.google_oauth import calendar_service
from services.redis_services import has_idempotency, set_idempotency


def _idem_key(title: str, start: str, end: str, attendees: list[str]) -> str:
    src = f"{title}|{start}|{end}|{','.join(sorted(attendees))}"
    return hashlib.sha256(src.encode()).hexdigest()


def _get_google_not_linked_error() -> dict[str, Any]:
    settings = get_settings()
    redirect_url = settings.google_redirect_uri.replace("/oauth/callback", "/oauth/start")
    code = "not_authenticated"
    message = f"Please link your Google account with the Calendar MCP: {redirect_url}"
    return {"error": {"code": code, "message": message}}


def freebusy(window_start: str, window_end: str, calendars: list[str] | None = None) -> Any:
    svc = calendar_service()
    if not svc:
        return _get_google_not_linked_error()
    body = {
        "timeMin": window_start,
        "timeMax": window_end,
        "items": [{"id": c} for c in (calendars or ["primary"])],
    }
    return svc.freebusy().query(body=body).execute()


def create_event(
    title: str,
    start: str,
    end: str,
    attendees: list[str],
    description: str | None = None,
    location: str | None = None,
    conference: bool = False,
    color_id: str | None = "1",
) -> dict[str, Any]:
    svc = calendar_service()
    if not svc:
        return _get_google_not_linked_error()

    key = _idem_key(title, start, end, attendees)
    if has_idempotency(key):
        return {"status": "duplicate_ignored"}

    event: dict[str, Any] = {
        "summary": title,
        "start": {"dateTime": start},
        "end": {"dateTime": end},
        "attendees": [{"email": a} for a in attendees],
    }
    if description:
        event["description"] = description
    if location:
        event["location"] = location
    if conference:
        event["conferenceData"] = {"createRequest": {"requestId": key}}
    if color_id:
        event["colorId"] = color_id

    created = (
        svc.events()
        .insert(calendarId="primary", body=event, conferenceDataVersion=1 if conference else 0)
        .execute()
    )

    set_idempotency(key)
    return {
        "event_id": created.get("id"),
        "html_link": created.get("htmlLink"),
        "title": created.get("summary"),
        "start": created.get("start", {}).get("dateTime"),
        "end": created.get("end", {}).get("dateTime"),
        "attendees": [a.get("email") for a in created.get("attendees", [])],
    }
