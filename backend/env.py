import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

ENV_KEY = "ENV"
DEFAULT_ENV = "DEV"


@lru_cache(maxsize=1)
def load_environment() -> str:
    """
    Load environment variables from a .env file when available.

    Returns the resolved environment name.
    """
    current_env = os.getenv(ENV_KEY)

    dotenv_path = Path(__file__).resolve().parent / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path, override=False)

    return os.getenv(ENV_KEY, current_env or DEFAULT_ENV)

