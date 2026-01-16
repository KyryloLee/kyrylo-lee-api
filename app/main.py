import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Annotated

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status, Query, Body, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from sqlalchemy import Engine
from sqlmodel import create_engine, select, Session, insert, update

from app.models.base import Token, InviteCode, UserOut, UserIn, MCPRequest
from app.models.sql import Invitation_Codes, Users


SQL_ENGINE: Engine | None = None
PSW_HASH: PasswordHash | None = None


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
    db_url = os.getenv('POSTGRES_URL')
    SQL_ENGINE = create_engine(db_url, echo=True)


def get_user(login: str) -> Users | None:
    if SQL_ENGINE is None: create_sql_engine()
    with Session(SQL_ENGINE) as session:
        statement = select(Users).where(Users.login == login)
        result = session.exec(statement=statement).all()
    if len(result) < 1:
        return None
    return result[0]


def create_user(login: str, password: str) -> Users:
    if SQL_ENGINE is None: create_sql_engine()
    if get_user(login) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='User already exists.'
        ) 
    with Session(SQL_ENGINE, expire_on_commit=False) as session:
        hashed_password = get_password_hash(password)
        user = Users(
            login=login,
            hashed_password=hashed_password,
            can_invite=False
        )
        session.add(user)
        session.commit()
    return user


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


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> Users:
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate the credentials',
        headers={"WWW-Authenticate": "Bearer"}
    )
    token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid token.',
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
            raise credential_exception
        expiration = datetime.fromtimestamp(payload.get('exp'),  timezone.utc)
        if expiration < datetime.now(timezone.utc):
            raise token_exception
    except InvalidTokenError:
        raise token_exception
    user = get_user(login=username)
    if user is None:
        raise credential_exception
    return user


def get_invitation_code(code: str) -> Invitation_Codes | None:
    if SQL_ENGINE is None: create_sql_engine()
    with Session(SQL_ENGINE) as session:
        statement = select(Invitation_Codes).where(Invitation_Codes.code == code)
        invite = session.exec(statement=statement).one_or_none
    return invite
  

def use_invitation_code(code: str, revert: bool = False) -> Invitation_Codes:
    if SQL_ENGINE is None: create_sql_engine()
    with Session(SQL_ENGINE) as session:
        statement = select(Invitation_Codes).where(Invitation_Codes.code == code)
        invite = session.exec(statement=statement).one_or_none()
        if invite is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail='Invitation code not found.'
            )
        expired_invite = HTTPException(
            status_code=status.HTTP_410_GONE,
            detail='The invitation code has expired.'
        )
        # if expiration datetime exists, check the constrain    
        if invite.expires_at and invite.expires_at > datetime.now(timezone.utc):
            raise expired_invite
        # if max uses exists, check the constrain
        if invite.max_uses and invite.max_uses < invite.uses:
            raise expired_invite
        # update invitation code uses
        if revert:
            invite.uses = max(0, invite.uses - 1)
        else:
            invite.uses += 1
        session.add(invite)
        session.commit()
    return invite


@app.get("/")
def root():
    return {"message": "Hello! My name is Kyrylo Lee."}


@app.get("/about")
def get_dev() -> Dict[str, Any]:
    return {"message": ("The goal is to design and implement a robust, "
                        "high-performance REST API, strictly adhering "
                        "to strong backend development practices relevant "
                        "to a microservices architecture, for the purpose "
                        "of serving personal and professional data.")}


@app.get('/user')
def get_user_by_login(
    login: str, 
    current_user: Annotated[Users, Depends(get_current_user)]
) -> UserOut:
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Token is invalid.',
            headers={"WWW-Authenticate": "Bearer"}
        )
    user =  get_user(login)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f'The \'{login}\' not found.')
    return user


@app.post('/user', status_code=status.HTTP_201_CREATED)
def user_sign_in(
    invite_code: Annotated[str, Body()],
    user: UserIn
) -> UserOut:
    use_invitation_code(invite_code) # update invite code counter
    try:
        created_user = create_user(**user.model_dump())
    except:
        use_invitation_code(invite_code, revert=True) # revert invite code counter
        raise
    return created_user


@app.post("/token")
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(
        username=form_data.username, 
        password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'The {form_data.username} is not authorized.',
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=10)
    access_token = create_access_token(
        data={'iss': user.login},
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type='bearer')


@app.get('/invite', description='Check status of a invitation code.')
def get_invite_code(
    code: Annotated[str, Query(description='Invitation code.')], 
    _: Annotated[Users, Depends(get_current_user)]
) -> InviteCode:
    invite_code = get_invitation_code(invitation=code)
    if invite_code is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'The "{code}" does not exist.'
        )
    return invite_code


@app.post(
    '/invite', 
    status_code=status.HTTP_201_CREATED, 
    description='Create an invitation code.'
)
def register_code(
    current_user: Annotated[Users, Depends(get_current_user)],
    code: InviteCode
) -> InviteCode:
    if SQL_ENGINE is None: create_sql_engine()
    with Session(SQL_ENGINE) as session:
        new_code = Invitation_Codes(
            created_by=current_user.login,
            **code.model_dump()
        )
        session.add(new_code)
        session.commit()
    return code

@app.post("/mcp")
def mcp(req: Request):
    logging.info(f'MCP request: {req}')
    if req.get('method') == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req.get('id'),
            "result": {
                "tools": [
                    {
                        "about": {
                            "description": "Get general information about this API",
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "user_id": {"type": "string"}
                                },
                                "required": ["user_id"]
                            }
                        }
                    },
                    {
                        "search": {
                            "description": "Get general information about this API",
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "user_id": {"type": "string"}
                                },
                                "required": ["user_id"]
                            }
                        }
                    },
                    {
                        "fetch": {
                            "description": "Get general information about this API",
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "user_id": {"type": "string"}
                                },
                                "required": ["user_id"]
                            }
                        }
                    }
                ]
            }
        }
    elif req.get('method') == 'initialize':
        return {
            "jsonrpc": "2.0",
            "id": req.get('id'),
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "prompts": {
                        "listChanged": False
                    },
                    "resources": {
                        "subscribe": False,
                        "listChanged": False
                    },
                    "tools": {
                        "listChanged": False
                    }
                },
                "serverInfo": {
                    "name": "kyrylo-lee-api",
                    "version": "1.0.0"
                }
            }
        }
    return {"jsonrpc": "2.0", "id": req.get('id'), "error": {"code": -32601, "message": "Method not found"}}