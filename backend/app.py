from env import load_environment

load_environment()

import crypto
import settings
from database import init_db
from version import VERSION
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from auth import router as auth_router
from secret_manager import router as secrets_router

init_db()
crypto.warn_if_plaintext()


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


@app.get("/healthz")
def healthz():
    """Liveness and readiness probe. Cheap on purpose: no database round trip."""
    return {"ok": True, "version": VERSION}


app.include_router(auth_router)
app.include_router(secrets_router)
