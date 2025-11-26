import os
from typing import Dict, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from sqlmodel import create_engine, select, Session, SQLModel, Field
from sqlalchemy import Engine


SQL_ENGINE: Engine | str = None

class Users(SQLModel, table=True):
    id: int | None = Field(primary_key=True)
    login: str = Field(unique=True)
    hashed_password: str
    can_invite: bool


load_dotenv() # loading the ".env" file
app = FastAPI()


def create_sql_engine() -> None:
    global SQL_ENGINE
    db_url = os.getenv('DEV_POSTGRES_URL')
    db_url = db_url.replace('postgres:', 'postgresql+psycopg2:')
    SQL_ENGINE = create_engine(db_url, echo=True)


def get_user(login: str) -> Users | None:
    if SQL_ENGINE is None: create_sql_engine()
    with Session(SQL_ENGINE) as session:
        statement = select(Users).where(Users.login == login)
        result = session.exec(statement=statement).all()
    if len(result) < 1:
        return None
    return result[0]


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


@app.get('/invite')
async def create_invite_token():
    return

@app.get('/users/{user_login}')
async def get_user_by_login(user_login: str):
    result =  get_user(user_login)
    if result is None:
        raise HTTPException(status_code=404, detail=f'The \'{user_login}\' not found.')
    return {
        'id': result.id,
        'login': result.login,
        'can_invite': result.can_invite
    }
