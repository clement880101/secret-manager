"""Re-encrypt every stored secret with the current key.

Rotation happens in two steps, and this is the second.

  1. Generate a new key. Set SECRET_ENCRYPTION_KEY to it and put the previous
     one in SECRET_ENCRYPTION_KEYS_RETIRED. Deploy. Everything keeps working:
     new writes use the new key, old values still decrypt with the retired one.

  2. Run this. It rewrites every value that was not written with the current
     key. When it reports nothing left, remove SECRET_ENCRYPTION_KEYS_RETIRED
     and deploy again.

Doing it this way means no downtime and no window where a value is unreadable.
Swapping the key in one step makes every existing secret permanently
unrecoverable, which is what this exists to prevent.

    docker run --rm -e DB_URL=... -e SECRET_ENCRYPTION_KEY=... \\
      -e SECRET_ENCRYPTION_KEYS_RETIRED=... \\
      ghcr.io/clement880101/secret-manager:latest python rotate_keys.py
"""

import sys

from env import load_environment

load_environment()

import crypto  # noqa: E402
from database import session_scope  # noqa: E402


def rotate(batch_size: int = 500) -> dict:
    """Rewrite values not encrypted with the current key. Returns a summary."""
    import auth.models  # noqa: F401  (registers the mapping)
    from secret_manager.models import Secret

    if not crypto.encryption_enabled():
        raise SystemExit(
            "SECRET_ENCRYPTION_KEY is not set. There is nothing to rotate to."
        )

    examined = rewritten = 0
    last_id = 0

    # Paginate by primary key, not OFFSET. OFFSET without ORDER BY assumes a
    # stable scan order, and there is none: rewriting a row writes a new tuple,
    # which moves it, so later pages skip rows that earlier pages pushed past.
    # With 1200 secrets in batches of 500 this silently left 500 of them on the
    # old key -- and dropping the retired key then made them unreadable, in the
    # one procedure that exists to stop exactly that.
    #
    # Ids never change, so ordering by id is stable under rewriting.
    while True:
        with session_scope() as db:
            rows = (
                db.query(Secret)
                .filter(Secret.id > last_id)
                .order_by(Secret.id)
                .limit(batch_size)
                .all()
            )
            if not rows:
                break
            for secret in rows:
                last_id = secret.id
                examined += 1
                if not crypto.needs_reencryption(secret.value):
                    continue
                # Decrypt with whichever key wrote it, store under the current one.
                secret.value = crypto.encrypt_value(crypto.decrypt_value(secret.value))
                rewritten += 1

    # Check rather than assume. Anything still on an old key here would become
    # unreadable the moment the retired key is dropped, so the caller has to
    # know before that happens.
    # Streamed, not .all(). The loop above is batched precisely so a large
    # deployment does not have to fit in memory; materialising every value here
    # would give that back, and values run to 64KiB each.
    remaining = 0
    with session_scope() as db:
        for (value,) in db.query(Secret.value).yield_per(batch_size):
            if crypto.needs_reencryption(value):
                remaining += 1

    return {"examined": examined, "rewritten": rewritten, "remaining": remaining}


if __name__ == "__main__":
    summary = rotate()
    print(
        f"Examined {summary['examined']} secrets, re-encrypted {summary['rewritten']}."
    )
    if summary["remaining"]:
        print(
            f"WARNING: {summary['remaining']} are still on an old key. Do NOT drop "
            "SECRET_ENCRYPTION_KEYS_RETIRED yet -- run this again and, if the number "
            "does not reach zero, report it before changing anything."
        )
        sys.exit(1)
    print("Nothing left on an old key. Safe to drop SECRET_ENCRYPTION_KEYS_RETIRED.")
    sys.exit(0)
