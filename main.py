from fastapi import FastAPI

app = FastAPI()


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