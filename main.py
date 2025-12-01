import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Annotated

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel
from sqlalchemy import Engine
from sqlmodel import create_engine, select, Session, SQLModel, Field


SQL_ENGINE: Engine | None = None
PSW_HASH: PasswordHash | None = None


class Users(SQLModel, table=True):
    id: int | None = Field(primary_key=True)
    login: str = Field(unique=True)
    hashed_password: str
    can_invite: bool


class UserData(BaseModel):
    id: int
    login: str
    can_invite: bool


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class Invitation_Codes(SQLModel, table=True):
    id: int = Field(primary_key=True)
    code: str = Field(unique=True)
    created_at: datetime
    expires_at: datetime
    max_uses: int
    uses: int


class InviteCodeData(BaseModel):
    code: str
    created_at: datetime
    expires_at: datetime
    max_uses: int
    uses: int


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
load_dotenv() # loading the ".env" file
app = FastAPI()


def create_psw_hash() -> None:
    global PSW_HASH
    PSW_HASH = PasswordHash.recommended()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if PSW_HASH is None: create_psw_hash()
    return PSW_HASH.verify(password=plain_password, hash=hashed_password)


def get_password_hash(password) -> str:
    if PSW_HASH is None: create_psw_hash()
    return PSW_HASH.hash(password=password)
 

def create_sql_engine() -> None:
    global SQL_ENGINE
    db_url = os.getenv('DEV_POSTGRES_URL')
    SQL_ENGINE = create_engine(db_url, echo=True)


def get_user(login: str) -> Users | None:
    if SQL_ENGINE is None: create_sql_engine()
    with Session(SQL_ENGINE) as session:
        statement = select(Users).where(Users.login == login)
        result = session.exec(statement=statement).all()
    if len(result) < 1:
        return None
    return result[0]


def authenticate_user(username: str, password: str) -> Users | None:
    user = get_user(login=username)
    if user is None:
        return None
    if not verify_password(plain_password=password, hashed_password=user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    secret_key = os.getenv('SECRET_KEY')
    algorithm = os.getenv('ALGORITHM')
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> Users:
    credentail_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate the credentails',
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(
            jwt=token,
            key=os.getenv('SECRET_KEY'),
            algorithms=[os.getenv('ALGORITHM')]
        )
        username = payload.get('iss')
        if username is None:
            raise credentail_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentail_exception
    user = get_user(login=token_data.username)
    if user is None:
        raise credentail_exception
    return user


def get_invitation_code(code: str) -> Invitation_Codes | None:
    if SQL_ENGINE is None: create_sql_engine()
    with Session(SQL_ENGINE) as session:
        statement = select(Invitation_Codes).where(Invitation_Codes.code == code)
        response = session.exec(statement=statement).all()
        if len(response) < 1:
            return None
        return response[0]


@app.get("/")
async def root():
    return {"message": "Hello! My name is Kyrylo Lee."}


@app.get("/about")
async def get_dev() -> Dict[str, Any]:
    return {"message": ("The goal is to design and implement a robust, "
                        "high-performance REST API, strictly adhering "
                        "to strong backend development practices relevant "
                        "to a microservices architecture, for the purpose "
                        "of serving personal and professional data.")}


@app.get('/user')
async def get_user_by_login(
    login: str, 
    current_user: Annotated[Users, Depends(get_current_user)]
) -> UserData:
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Token is invalid.',
            headers={"WWW-Authenticate": "Bearer"}
        )
    result =  get_user(login)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f'The \'{login}\' not found.')
    return UserData(
        id=result.id,
        login=result.login,
        can_invite=result.can_invite
    )

@app.post('/user')
async def user_sign_in():
    return None


@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(
        username=form_data.username, 
        password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'The {form_data.username} is not authorised.',
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=10)
    access_token = create_access_token(
        data={'iss': user.login},
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type='bearer')


@app.get('/invite', description='Check status of a invitation code.')
async def get_invite_code(
    code: str, 
    current_user: Annotated[Users, Depends(get_current_user)]
) -> InviteCodeData:
    invite_code = get_invitation_code(invitation=code)
    if invite_code is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'The "{code}" does not exist.'
        )
    return invite_code

@app.post('/invite', description='Activate an invitation code.')
async def register_code():
    return None

