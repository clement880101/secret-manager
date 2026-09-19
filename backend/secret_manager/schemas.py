"""Request shapes, with limits.

Every bound here exists because without it one authenticated account could
write until the disk filled: a 20MB value and a 100,000-character key were both
accepted before these were added. The numbers are generous for real secrets --
a certificate chain or an SSH key fits comfortably -- and small enough that
abuse is bounded.
"""

from pydantic import BaseModel, Field


# Long enough for a certificate chain or a private key, far short of a file.
MAX_VALUE_LENGTH = 64 * 1024
MAX_KEY_LENGTH = 256
MAX_USER_ID_LENGTH = 64


class SecretIn(BaseModel):
    # No slashes: the key is a single path segment in /secrets/{key}, so a key
    # containing "/" could be created and then never read or deleted. It sat in
    # `list` forever, unreachable. Percent-encoding does not help -- the server
    # decodes before routing, so %2F splits the path just the same.
    key: str = Field(..., min_length=1, max_length=MAX_KEY_LENGTH, pattern=r"^[^/\x00-\x1f]+$")
    value: str = Field(..., min_length=1, max_length=MAX_VALUE_LENGTH)


class ShareIn(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=MAX_USER_ID_LENGTH)
