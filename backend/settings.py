"""Security-relevant configuration, read from the environment.

Every switch here defaults to the safe choice, so a fresh self-hosted
deployment is locked down until its operator opts out.
"""

import os
from typing import List


TRUTHY = {"1", "true", "yes", "on"}


def bool_env(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable.

    Inputs:
        name (str): Environment variable to read.
        default (bool): Value used when the variable is unset or empty.
    Outputs:
        bool: True when the value is one of 1/true/yes/on, case-insensitive.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in TRUTHY


def allowed_origins() -> List[str]:
    """Return the CORS origins this deployment accepts.

    Empty by default: the API is consumed by a CLI, which is not subject to
    the same-origin policy and therefore needs no CORS grant at all.
    """
    raw = os.getenv("ALLOWED_ORIGINS", "")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def docs_enabled() -> bool:
    """Whether to serve the interactive API docs and the OpenAPI schema."""
    return bool_env("ENABLE_API_DOCS", default=False)


def test_login_enabled() -> bool:
    """Whether to expose POST /auth/login-test.

    That route swaps a GitHub personal access token for a session. It is how
    the integration suite authenticates without a browser. It is not an
    authentication bypass -- the token is still validated against GitHub --
    but it is a second way in, so it stays off unless a deployment asks for it.
    """
    return bool_env("ENABLE_TEST_LOGIN", default=False)


def token_cache_ttl_seconds() -> int:
    """How long a verified GitHub token stays trusted before revalidation.

    Without this the API calls GitHub once per request, which burns the
    deployment's rate limit and lets an attacker amplify traffic against it.
    Zero disables caching.
    """
    try:
        return max(0, int(os.getenv("TOKEN_CACHE_TTL_SECONDS", "300")))
    except ValueError:
        return 300


def auth_mode() -> str:
    """Return "local" or "github".

    Defaults to whichever the deployment is actually configured for, so that
    pulling the image and running it works with no setup at all, while an
    existing GitHub deployment keeps behaving exactly as before.

    Explicit AUTH_MODE wins. Otherwise: GitHub if an OAuth app is configured,
    local if not.
    """
    explicit = os.getenv("AUTH_MODE", "").strip().lower()
    if explicit in {"local", "github"}:
        return explicit
    if os.getenv("OAUTH_ID_GITHUB") and os.getenv("OAUTH_SECRET_GITHUB"):
        return "github"
    return "local"


def bootstrap_token() -> str:
    """A first token to hand out, instead of one generated at startup.

    Useful when the deployment is immutable or the logs are awkward to read.
    """
    return os.getenv("BOOTSTRAP_TOKEN", "").strip()


def registration_open() -> bool:
    """Whether anyone who can reach the service may create an account.

    Open by default, so a freshly started deployment is usable by the people it
    was started for without an administrator handing out tokens first. An
    account only ever grants access to its own secrets plus whatever is shared
    with it, so this is not a way into anyone else's data -- but close it with
    ALLOW_REGISTRATION=false on anything reachable from the open internet.
    """
    return bool_env("ALLOW_REGISTRATION", default=True)


def auth_rate_limit() -> int:
    """Failed authentications allowed per key per window. 0 disables the limit."""
    try:
        return max(0, int(os.getenv("AUTH_RATE_LIMIT", "10")))
    except ValueError:
        return 10


def auth_rate_window_seconds() -> int:
    """How long failures are counted for."""
    try:
        return max(1, int(os.getenv("AUTH_RATE_WINDOW_SECONDS", "900")))
    except ValueError:
        return 900
