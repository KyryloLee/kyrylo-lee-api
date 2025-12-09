from datetime import datetime, timezone

from pydantic import BaseModel, Field


DATE_FORMAT: str = '%Y%m%d'


class UserOut(BaseModel):
    id: int
    login: str
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
        description=f'Expiration date UTC. Format = YYYY-MM-DD'
    )
    max_uses: int | None = None
