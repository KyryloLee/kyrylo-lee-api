import os
import uuid
from typing import Dict, Any
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI

UUID = None

@asynccontextmanager
async def lifspan(app: FastAPI):
    yield


load_dotenv() # loading the ".env" file
app = FastAPI(lifespan=lifspan)

def get_uuid() -> str:
    global UUID
    if UUID is None:
        UUID = uuid.uuid1()
    return UUID


@app.get("/")
async def root():
    return {"message": "Hello! My name is Kyrylo Lee."}


@app.get("/about")
async def get_dev() -> Dict[str, Any]:
    return {
        "id": get_uuid(),
        "message": ("The goal is to design and implement a robust, "
                    "high-performance REST API, strictly adhering "
                    "to strong backend development practices relevant "
                    "to a microservices architecture, for the purpose "
                    "of serving personal and professional data.")
    }
