import os
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker


DB_URL = os.environ.get("DB_URL", "sqlite:///./secrets.db")
engine = create_engine(DB_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Any stable number. It only has to be the same in every replica.
SCHEMA_LOCK_KEY = 0x5EC12E7


@contextmanager
def _schema_lock():
    """Hold a database-wide lock while the schema is being set up.

    Replicas start at the same time, and creating the schema is check-then-act:
    create_all() asks which tables exist and then creates the ones that do not.
    Two replicas can both find a table missing and both issue CREATE TABLE. One
    wins; the others die on Postgres's own catalog index with

        UniqueViolation: duplicate key value violates unique constraint
        "pg_type_typname_nsp_index"

    which is a crash on the documented way to run this -- `--scale api=3`,
    `kubectl scale --replicas=10`. It is intermittent, which is worse than
    reliable: it showed up in roughly one cold start in four here.

    Applying migrations has the same shape, so it is inside the lock too:
    otherwise two replicas both read the applied list and both run the step.

    Only Postgres has advisory locks, and only Postgres needs them: SQLite
    backs a single container, which is why the clustered deployment requires
    Postgres in the first place.
    """
    if engine.dialect.name != "postgresql":
        yield
        return

    connection = engine.connect()
    try:
        connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": SCHEMA_LOCK_KEY})
        connection.commit()
        yield
    finally:
        try:
            connection.execute(
                text("SELECT pg_advisory_unlock(:key)"), {"key": SCHEMA_LOCK_KEY}
            )
            connection.commit()
        finally:
            connection.close()


def init_db() -> None:
    import audit_models  # noqa: F401
    from auth import models as auth_models  # noqa: F401
    from secret_manager import models as secret_models  # noqa: F401

    # create_all() only adds missing tables. Anything that changes an existing
    # one goes through migrations, so an upgrade never means recreating the
    # database.
    from migrations import run_migrations

    with _schema_lock():
        Base.metadata.create_all(bind=engine)
        run_migrations()

