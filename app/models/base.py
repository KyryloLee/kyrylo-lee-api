from datetime import datetime, timezone

from pydantic import BaseModel, Field


DATE_FORMAT: str = '%Y%m%d'


class BaseUser(BaseModel):
    login: str
 

class UserIn(BaseUser):
    password: str

class UserOut(BaseUser):
    can_invite: bool


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class InviteCode(BaseModel):
    code: str = Field(description='An invitation code.')
    expires_at: datetime | None = Field(
        default=None,
        description=f'Expiration date. RFC 3339 format.'
    )
    max_uses: int | None = None


class MCPRequest(BaseModel):
    jsonrpc: str
    method: str
    id: int | str
    params: dict | None = None
