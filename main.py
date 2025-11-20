import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from sqlmodel import Field, SQLModel, create_engine

ENGINE = None

class Users(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_name: str
    nick_name: str


def create_db_and_tables() -> None:
    load_dotenv()
    db_url = os.getenv('DEV_POSTGRES_URL')
    db_url = db_url.replace('postgres:', 'postgresql+psycopg2:')
    engine = create_engine(db_url, echo=True)
    SQLModel.metadata.create_all(engine)


@asynccontextmanager
async def lifspan(app: FastAPI):
    create_db_and_tables()
    yield

load_dotenv() # loading the ".env" file
app = FastAPI(lifespan=lifspan)


@app.get("/")
async def root():
    return {"message": "Hello! My name is Kyrylo Lee."}

@app.get("/about")
async def get_dev():
    return {"message": ("The goal is to design and implement a robust, "
                        "high-performance REST API, strictly adhering "
                        "to strong backend development practices relevant "
                        "to a microservices architecture, for the purpose "
                        "of serving personal and professional data.")}
