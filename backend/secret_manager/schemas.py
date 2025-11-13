from pydantic import BaseModel, Field


class SecretIn(BaseModel):
    key: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)


class ShareIn(BaseModel):
    github_id: str
    can_write: bool = True

