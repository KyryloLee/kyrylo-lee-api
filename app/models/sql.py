from datetime import datetime, timezone

from sqlmodel import SQLModel, Field


class Users(SQLModel, table=True):
    id: int | None = Field(primary_key=True)
    login: str = Field(unique=True)
    hashed_password: str
    can_invite: bool


class Invitation_Codes(SQLModel, table=True):
    id: int = Field(primary_key=True)
    code: str = Field(unique=True)
    created_at: datetime = datetime.now(timezone.utc)
    expires_at: datetime
    max_uses: int
    uses: int = 0
    created_by: str
    updated_by: str
