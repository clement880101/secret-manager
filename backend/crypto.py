"""Envelope encryption for secret values stored in the database.

Values are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using a key
supplied as SECRET_ENCRYPTION_KEY. Ciphertext is tagged with a version prefix
so a database holding rows written before encryption was switched on can still
be read, and so the scheme can be rotated later without guesswork.

The key is optional rather than mandatory on purpose: this project deploys on
merge, and hard-failing a running deployment that has no key configured yet
would take it offline. Absent a key the service logs a prominent warning and
stores plaintext, exactly as it did before.
"""

import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


LOGGER = logging.getLogger(__name__)

# Marks a value this module produced. Anything without it is a legacy plaintext
# row written before encryption was enabled.
CIPHERTEXT_PREFIX = "enc:v1:"

_WARNED = False


def _key() -> Optional[bytes]:
    raw = os.getenv("SECRET_ENCRYPTION_KEY", "").strip()
    return raw.encode("utf-8") if raw else None


def _retired_keys() -> list:
    """Keys that can still decrypt, but are no longer used to encrypt.

    Rotation is otherwise all-or-nothing: swapping SECRET_ENCRYPTION_KEY makes
    every existing value unreadable, because nothing can decrypt what the old
    key wrote. Listing the previous key here lets the new one take over while
    old ciphertext stays readable, so a rotation can be done without downtime
    and without re-encrypting everything first.
    """
    raw = os.getenv("SECRET_ENCRYPTION_KEYS_RETIRED", "")
    return [k.strip().encode("utf-8") for k in raw.split(",") if k.strip()]


def encryption_enabled() -> bool:
    """Whether a usable encryption key is configured."""
    return _key() is not None


def _cipher() -> Optional[MultiFernet]:
    """The cipher stack: the current key first, then any retired ones.

    MultiFernet encrypts with the first key and decrypts with whichever one
    works, which is exactly the shape a rotation needs.
    """
    key = _key()
    if key is None:
        return None
    try:
        return MultiFernet([Fernet(k) for k in [key] + _retired_keys()])
    except (ValueError, TypeError) as exc:
        # A malformed key is a deployment error, not something to paper over:
        # encrypting with a broken key would silently lose data.
        raise RuntimeError(
            "SECRET_ENCRYPTION_KEY is not a valid Fernet key. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        ) from exc


def warn_if_plaintext() -> None:
    """Log once if secrets are going to disk unencrypted."""
    global _WARNED
    if encryption_enabled() or _WARNED:
        return
    _WARNED = True
    LOGGER.warning(
        "SECRET_ENCRYPTION_KEY is not set: secret values are being stored in "
        "plaintext. Set it to a Fernet key to encrypt them at rest."
    )


def encrypt_value(value: str) -> str:
    """Encrypt a secret value for storage, or return it unchanged if no key."""
    cipher = _cipher()
    if cipher is None:
        warn_if_plaintext()
        return value
    return CIPHERTEXT_PREFIX + cipher.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_value(stored: str) -> str:
    """Decrypt a stored value, passing through rows written before encryption.

    Raises:
        RuntimeError: the row is ciphertext but no key (or the wrong key) is
            configured. Returning the raw ciphertext to a caller would hand
            them garbage and look like corruption, so fail loudly instead.
    """
    if not stored.startswith(CIPHERTEXT_PREFIX):
        return stored

    cipher = _cipher()
    if cipher is None:
        raise RuntimeError(
            "Stored secret is encrypted but SECRET_ENCRYPTION_KEY is not set."
        )
    token = stored[len(CIPHERTEXT_PREFIX):].encode("ascii")
    try:
        return cipher.decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "Stored secret could not be decrypted with any configured key. "
            "If SECRET_ENCRYPTION_KEY was changed, add the previous key to "
            "SECRET_ENCRYPTION_KEYS_RETIRED so existing values stay readable."
        ) from exc


def needs_reencryption(stored: str) -> bool:
    """Whether a stored value was written with something other than the current key."""
    if not stored.startswith(CIPHERTEXT_PREFIX):
        return True  # legacy plaintext
    key = _key()
    if key is None:
        return False
    try:
        # Decrypting with the current key alone succeeds only if it wrote this.
        Fernet(key).decrypt(stored[len(CIPHERTEXT_PREFIX):].encode("ascii"))
        return False
    except (InvalidToken, ValueError, TypeError):
        return True
