from pydantic import BaseModel


class LoginTestRequest(BaseModel):
    token: str

