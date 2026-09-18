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

from cryptography.fernet import Fernet, InvalidToken


LOGGER = logging.getLogger(__name__)

# Marks a value this module produced. Anything without it is a legacy plaintext
# row written before encryption was enabled.
CIPHERTEXT_PREFIX = "enc:v1:"

_WARNED = False


def _key() -> Optional[bytes]:
    raw = os.getenv("SECRET_ENCRYPTION_KEY", "").strip()
    return raw.encode("utf-8") if raw else None


def encryption_enabled() -> bool:
    """Whether a usable encryption key is configured."""
    return _key() is not None


def _cipher() -> Optional[Fernet]:
    key = _key()
    if key is None:
        return None
    try:
        return Fernet(key)
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
            "Stored secret could not be decrypted with the configured "
            "SECRET_ENCRYPTION_KEY. The key may have been rotated or replaced."
        ) from exc
