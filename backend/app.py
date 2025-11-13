from env import load_environment

load_environment()

from database import init_db
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from auth import router as auth_router
from secret_manager import router as secrets_router

init_db()


app = FastAPI(title="Secret Manager (Local SQLite)")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

@app.get("/healthz")
def healthz():
    return {"ok": True}

app.include_router(auth_router)
app.include_router(secrets_router)
