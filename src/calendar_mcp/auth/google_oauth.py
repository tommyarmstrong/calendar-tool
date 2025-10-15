from typing import Any

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from app.config import settings
from services.redis_services import load_tokens, save_tokens


def _client_config() -> dict[str, dict[str, str | list[str]]]:
    return {
        "web": {
            "client_id": settings.google_client_id,
            "project_id": "local-dev",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_secret": settings.google_client_secret,
            "redirect_uris": [settings.google_redirect_uri],
        }
    }


def oauth_flow() -> Flow:
    flow = Flow.from_client_config(_client_config(), scopes=settings.google_scopes)
    flow.redirect_uri = settings.google_redirect_uri
    return flow


def start_auth_url(state: str = "state") -> str:
    flow = oauth_flow()
    url, _ = flow.authorization_url(access_type="offline", prompt="consent", state=state)
    # Type assertion: authorization_url returns a string URL
    assert isinstance(url, str)
    return url


def finish_auth(code: str) -> dict[str, str | None]:
    flow = oauth_flow()
    flow.fetch_token(code=code)
    creds = flow.credentials
    tokens = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
        "expiry": creds.expiry.isoformat() if creds.expiry else None,
    }
    save_tokens(tokens)
    return tokens


def get_creds() -> Credentials | None:
    tokens = load_tokens()
    if not tokens:
        return None
    return Credentials(
        tokens["token"],
        refresh_token=tokens.get("refresh_token") or None,
        token_uri=str(tokens["token_uri"]),
        client_id=str(tokens["client_id"]),
        client_secret=str(tokens["client_secret"]),
        scopes=list(tokens["scopes"] or []),
    )


def calendar_service() -> Any | None:
    creds = get_creds()
    if not creds:
        return None
    return build("calendar", "v3", credentials=creds, cache_discovery=False)
