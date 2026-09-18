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
