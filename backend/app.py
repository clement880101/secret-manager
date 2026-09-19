from env import load_environment

load_environment()

import crypto
import settings
from database import init_db, session_scope
from version import VERSION
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from auth import router as auth_router
from secret_manager import router as secrets_router

init_db()
crypto.warn_if_plaintext()

# A fresh deployment has no way in until a token exists, so make one and print
# it. Does nothing once any token is present.
from auth.local import ensure_bootstrap_token  # noqa: E402

ensure_bootstrap_token()


# The interactive docs and the schema describe every route to anyone who asks,
# so they are opt-in rather than on by default.
_docs = settings.docs_enabled()

app = FastAPI(
    title="Secret Manager",
    summary="A lightweight, distributed secret manager.",
    description=(
        "Store secrets, share them with other GitHub users, and read them back "
        "from anywhere. State lives in the database rather than in process "
        "memory, so this runs behind a load balancer across as many replicas "
        "as you like."
    ),
    version=VERSION,
    docs_url="/docs" if _docs else None,
    redoc_url="/redoc" if _docs else None,
    openapi_url="/openapi.json" if _docs else None,
)

# No browser client ships with this project, so the default grant is nothing at
# all. Deployments that add a web frontend set ALLOWED_ORIGINS explicitly.
_origins = settings.allowed_origins()
if _origins:
    # "*" and credentials are mutually exclusive per the CORS spec, and browsers
    # reject the combination -- so a wildcard origin drops credentials.
    _wildcard = "*" in _origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=not _wildcard,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )


# Pydantic validates after the whole body is read, so a field limit alone still
# lets a caller make the process buffer an arbitrarily large request. This
# refuses it from the Content-Length header instead.
@app.middleware("http")
async def limit_request_size(request, call_next):
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > settings.max_request_bytes():
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
    return await call_next(request)


@app.get("/metrics")
def metrics():
    """Prometheus text format, hand-rolled.

    Deliberately no client library: four counts do not justify a dependency in
    an image whose point is being small. Off unless ENABLE_METRICS is set,
    because the counts are not something every deployment wants on an
    unauthenticated endpoint.
    """
    if not settings.metrics_enabled():
        raise HTTPException(404, "Not Found")

    import audit_models
    from auth.models import ApiToken, User
    from secret_manager.models import Secret, Share

    with session_scope() as db:
        counts = {
            "secretmgr_users_total": db.query(User).count(),
            "secretmgr_secrets_total": db.query(Secret).count(),
            "secretmgr_shares_total": db.query(Share).count(),
            "secretmgr_tokens_total": db.query(ApiToken).count(),
            "secretmgr_audit_events_total": db.query(audit_models.AuditEvent).count(),
        }

    lines = []
    for name, value in counts.items():
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")
    lines.append("# TYPE secretmgr_build_info gauge")
    lines.append(f'secretmgr_build_info{{version="{VERSION}"}} 1')
    return PlainTextResponse("\n".join(lines) + "\n")


@app.get("/healthz")
def healthz():
    """Liveness and readiness probe. Cheap on purpose: no database round trip."""
    return {"ok": True, "version": VERSION}


app.include_router(auth_router)
app.include_router(secrets_router)
