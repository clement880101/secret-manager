"""Schema changes that create_all() cannot make.

SQLAlchemy's create_all() adds tables that are missing and does nothing else.
It will not add a column to a table that already exists, so before this the
only upgrade path for such a change was "recreate the database", which for a
secret manager means losing everything.

This is deliberately small: an ordered list of steps, a table recording which
have run, and each step wrapped in its own transaction. Alembic would do more,
but it would also add a dependency and a workflow to an image whose point is
that you pull it and run it. If the schema ever outgrows this, that is the
moment to reach for Alembic -- not before.

Each step must be safe to run against a database that has already had it
applied, because a crash between applying a step and recording it is possible.
"""

import logging
from typing import Callable, List, Tuple

from sqlalchemy import inspect, text

from database import engine, session_scope


LOGGER = logging.getLogger(__name__)

VERSION_TABLE = "schema_migrations"


def _ensure_version_table() -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS {VERSION_TABLE} "
                "(name VARCHAR(128) PRIMARY KEY, applied_at DOUBLE PRECISION)"
                if engine.dialect.name != "sqlite"
                else f"CREATE TABLE IF NOT EXISTS {VERSION_TABLE} "
                "(name VARCHAR(128) PRIMARY KEY, applied_at REAL)"
            )
        )


def _applied() -> set:
    with engine.begin() as conn:
        rows = conn.execute(text(f"SELECT name FROM {VERSION_TABLE}"))
        return {row[0] for row in rows}


def _record(name: str) -> None:
    import time

    with engine.begin() as conn:
        conn.execute(
            text(f"INSERT INTO {VERSION_TABLE} (name, applied_at) VALUES (:n, :t)"),
            {"n": name, "t": time.time()},
        )


def column_exists(table: str, column: str) -> bool:
    """Whether a column is already present, so a step can be re-run safely."""
    try:
        return any(c["name"] == column for c in inspect(engine).get_columns(table))
    except Exception:  # noqa: BLE001 - a missing table means a missing column
        return False


def table_exists(table: str) -> bool:
    return inspect(engine).has_table(table)


# --- the steps, in order ----------------------------------------------------
#
# Add new ones at the end and never edit one that has shipped: a database that
# already recorded it will not run it again.
#
# A step takes no arguments and is responsible for being idempotent.

MIGRATIONS: List[Tuple[str, Callable[[], None]]] = []


def run_migrations() -> List[str]:
    """Apply any steps that have not run. Returns the names applied."""
    _ensure_version_table()
    done = _applied()
    applied = []
    for name, step in MIGRATIONS:
        if name in done:
            continue
        LOGGER.info("Applying schema migration %s", name)
        step()
        _record(name)
        applied.append(name)
    return applied
