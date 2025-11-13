import importlib
import sys
from pathlib import Path

import pytest


MODULES_TO_CLEAR = [
    "secret_manager.service",
    "secret_manager.models",
    "secret_manager.router",
    "secret_manager.schemas",
    "auth.models",
    "auth.router",
    "auth.service",
    "database",
]


@pytest.fixture()
def service_modules(monkeypatch):
    """Reload core modules against an in-memory SQLite database for isolation."""
    monkeypatch.setenv("DB_URL", "sqlite:///:memory:")

    project_root = Path(__file__).resolve().parent.parent
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)

    for name in MODULES_TO_CLEAR:
        sys.modules.pop(name, None)

    database = importlib.import_module("database")
    auth_models = importlib.import_module("auth.models")
    secret_models = importlib.import_module("secret_manager.models")
    service = importlib.import_module("secret_manager.service")

    database.init_db()

    return {
        "database": database,
        "service": service,
        "User": auth_models.User,
        "Secret": secret_models.Secret,
        "Share": secret_models.Share,
    }


@pytest.fixture()
def auth_service_module(monkeypatch):
    """Reload auth service against an in-memory SQLite database for isolation."""
    monkeypatch.setenv("DB_URL", "sqlite:///:memory:")

    project_root = Path(__file__).resolve().parent.parent
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)

    for name in MODULES_TO_CLEAR:
        sys.modules.pop(name, None)

    database = importlib.import_module("database")
    auth_models = importlib.import_module("auth.models")
    importlib.import_module("secret_manager.models")
    auth_service = importlib.import_module("auth.service")

    database.init_db()

    return {
        "database": database,
        "service": auth_service,
        "User": auth_models.User,
    }


