from fastapi import FastAPI, Request,Response
from routers import users


app = FastAPI()
app.include_router(users.router,tags=['users'])


