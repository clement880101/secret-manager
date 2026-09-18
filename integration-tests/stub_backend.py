"""Run the real backend with only the GitHub API calls stubbed.

The integration suite drives the real CLI binary against a real server on a
real database. The one thing it cannot supply for itself is a GitHub identity:
the backend resolves a token by calling api.github.com.

It used to do that with two personal access tokens kept as repository secrets.
Those expire, and when they did the whole suite went red for reasons that had
nothing to do with the code under test. Credentials with an expiry date are a
poor foundation for CI.

So GitHub is stubbed here, in the test harness, rather than behind a flag in
the application. Nothing in backend/ knows this file exists, and there is no
switch in production code that could be turned on by accident.

What this still covers: the CLI talking to a real server over HTTP, real
request and response shapes, real persistence, real sharing and access control
between two distinct users. What it does not cover is GitHub's own OAuth, which
backend/tests exercises against a stubbed fetch_github_user in the same way.
"""

import os
import sys

BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.insert(0, BACKEND)
os.chdir(BACKEND)

import auth.service as auth_service  # noqa: E402

# Fixed tokens the suite logs in with. They are not secret and grant nothing:
# they are only meaningful to this stub.
USERS = {
    os.environ["STUB_TOKEN_1"]: 900000001,
    os.environ["STUB_TOKEN_2"]: 900000002,
}


def fake_fetch_github_user(access_token, token_kind="oauth"):
    """Resolve a token the way GitHub would, for the two identities we know."""
    from fastapi import HTTPException

    user_id = USERS.get(access_token)
    if user_id is None:
        raise HTTPException(401, "Invalid GitHub access token")
    return {
        "id": user_id,
        "login": f"stub-user-{user_id}",
        "name": f"Stub User {user_id}",
        "avatar_url": None,
    }


auth_service.fetch_github_user = fake_fetch_github_user

if __name__ == "__main__":
    import uvicorn
    from app import app

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
