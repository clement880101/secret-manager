from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from . import schemas, service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
def login(scope: str = Query(default="read:user user:email", description="GitHub OAuth scopes")):
    try:
        return service.initiate_login(scope=scope)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, "Failed to prepare GitHub login") from exc


@router.get("/login/{session_id}")
def poll_login(session_id: str):
    try:
        return service.get_session_status(session_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, "Failed to load login session") from exc


@router.get("/callback", response_class=HTMLResponse)
def callback(code: str, state: str):
    session_id = None
    try:
        session_id, token_payload = service.exchange_code_for_token(code, state)
        user = service.verify_access_token(token_payload["access_token"])
        service.get_or_create_user(user["id"])
        service.complete_session(session_id, token_payload, user)
    except HTTPException as exc:
        if session_id:
            service.fail_session(session_id, str(exc.detail) if hasattr(exc, "detail") else "Login failed")
        raise
    except Exception as exc:
        if session_id:
            service.fail_session(session_id, "Unexpected error during login")
        raise HTTPException(500, "Failed to finalize GitHub login") from exc
    return HTMLResponse(
        content="<html><body><h1>Authentication Complete</h1><p>You can close this window and return to the CLI.</p></body></html>"
    )


@router.post("/login-test")
def login_test(payload: schemas.LoginTestRequest):
    try:
        return service.login_with_personal_token(payload.token)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, "Failed to verify GitHub token") from exc

