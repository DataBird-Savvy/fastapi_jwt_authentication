from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from enum import Enum
from typing import Optional
from auth import router as auth_router
import models
from database import engine
from auth import get_current_user, get_db
from typing import Annotated


models.Base.metadata.create_all(bind=engine)


app = FastAPI()
app.include_router(auth_router)

db_dependancy=Annotated[Session,Depends(get_db)]
user_dependancy=Annotated[models.User,Depends(get_current_user)]





@app.get("/me")
async def read_current_user(current_user: user_dependancy,db: db_dependancy):
    if not current_user:
        return {"error":"Invalid Credentials"}
    return current_user.username