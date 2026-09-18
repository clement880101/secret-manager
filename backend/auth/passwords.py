"""Password hashing, using only the standard library.

scrypt is in hashlib, so this needs no dependency. Adding bcrypt or argon2
would mean another wheel in an image whose whole point is that you pull it and
run it, for no meaningful gain at this scale.

The encoded form carries its own parameters, so the cost can be raised later
without invalidating existing hashes.
"""

import base64
import hashlib
import hmac
import secrets

# Roughly 16MB and ~100ms per hash on current hardware: enough to make
# large-scale guessing expensive without making login feel slow.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32

MIN_PASSWORD_LENGTH = 8


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def hash_password(password: str) -> str:
    """Return an encoded hash carrying its own parameters and salt."""
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_BYTES
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(derived)}"


def verify_password(password: str, encoded: str) -> bool:
    """Check a password against an encoded hash, in constant time."""
    try:
        scheme, n, r, p, salt, expected = encoded.split("$")
        if scheme != "scrypt":
            return False
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_unb64(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(_unb64(expected)),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, _unb64(expected))
