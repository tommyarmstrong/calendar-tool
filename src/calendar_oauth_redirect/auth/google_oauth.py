from typing import Any

from app.config import settings
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from shared_infrastructure.cryptography_manager import get_fernet
from shared_infrastructure.redis_manager import build_redis_manager

_GOOGLE_TOKEN_TTL = 3600 * 24 * 14  # 14 days


fernet = get_fernet(settings.calendar_token_encryption_key.encode("utf-8"))
redis_manager = build_redis_manager(settings.redis_url, fernet=fernet)


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
    redis_manager.save_tokens("user1", tokens, ttl=_GOOGLE_TOKEN_TTL)
    return tokens


def get_creds() -> Credentials | None:
    tokens = redis_manager.load_tokens("user1")
    if not tokens:
        return None

    creds = Credentials(
        tokens["token"],
        refresh_token=tokens.get("refresh_token") or None,
        token_uri=str(tokens["token_uri"]),
        client_id=str(tokens["client_id"]),
        client_secret=str(tokens["client_secret"]),
        scopes=list(tokens["scopes"] or []),
    )

    # Check if token needs refresh
    return refresh_creds(creds)


def refresh_creds(creds: Credentials) -> Credentials | None:
    # Check if token needs refresh
    if not creds.expired:
        return creds

    if creds.expired and creds.refresh_token:
        try:
            # Refresh the token
            creds.refresh(Request())

            # Save the new tokens
            new_tokens = {
                "token": creds.token,
                "refresh_token": creds.refresh_token,
                "token_uri": creds.token_uri,
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "scopes": list(creds.scopes) if creds.scopes else [],
                "expiry": creds.expiry.isoformat() if creds.expiry else None,
            }
            redis_manager.save_tokens("user1", new_tokens, ttl=_GOOGLE_TOKEN_TTL)

            return creds

        except Exception as e:
            # Remove invalid tokens
            redis_manager.purge_tokens("user1")
            raise ValueError(f"Failed to refresh token: {e}") from e

    # Token is expired but no refresh token available
    redis_manager.purge_tokens("user1")
    return None


def calendar_service() -> Any | None:
    creds = get_creds()
    if not creds:
        return None
    return build("calendar", "v3", credentials=creds, cache_discovery=False)
