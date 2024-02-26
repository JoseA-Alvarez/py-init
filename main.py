from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import models
import database
from dotenv import load_dotenv
import os
from api.user_endpoint import router as user_router
from api.auth_endpoint import router as auth_router

load_dotenv()  # take environment variables from .env.


app = FastAPI()
app.include_router(user_router, prefix="/users", tags=["users"])
app.include_router(auth_router, prefix="", tags=["auth"])


models.database.Base.metadata.create_all(bind=database.engine)

origins = os.getenv('ORIGINS').split(',')

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




