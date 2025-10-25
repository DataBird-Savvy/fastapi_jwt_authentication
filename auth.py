from typing_extensions import Annotated
from jose import JWTError, jwt
from datetime import datetime, timedelta,timezone
from typing import Optional
from pydantic import BaseModel, ConfigDict
from fastapi import APIRouter, Depends, HTTPException, status
import models
from database import SessionLocal
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
import os
load_dotenv()
router= APIRouter(prefix="/auth",tags=["auth"])

SECRET_KEY=os.getenv("SECRET_KEY")
ALGORITHM=os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES=os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
REFRESH_TOKEN_EXPIRE_DAYS = os.getenv("REFRESH_TOKEN_EXPIRE_DAYS")

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


class CreateUserRequest(BaseModel):
    username:str
    email: str
    age:int
    password:str
    
  
class UserResponse(BaseModel):
    id:int
    username:str
    email:str
    age:int
    
    
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str
    
def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
        
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

        
db_dependancy=Annotated[Session,Depends(get_db)]


@router.post("/register",status_code=status.HTTP_201_CREATED,response_model=UserResponse)
async def register(user:CreateUserRequest,db:db_dependancy):
    hashed_password = pwd_context.hash(user.password)
    
    db_user = models.User(username=user.username, password=hashed_password, email=user.email, age=user.age)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.get("/registered_users",status_code=status.HTTP_200_OK,response_model=list[UserResponse])
async def get_registered_users(db:db_dependancy):
    users=db.query(models.User).all()
    return users

def authenticate_user(db:Session,username:str,password:str):
    user=db.query(models.User).filter(models.User.username==username).first()
    if not user:
        return False
    if not pwd_context.verify(password,user.password):
        return False
    return user
def create_access_token(username: str,id:str ,expires_delta: Optional[timedelta] = None):
    to_encode = {"sub": username,"id":id}
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
def create_refresh_token(username: str,id:str, expires_delta: Optional[timedelta] = None):
    to_encode = {"sub": username,"id":id}
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.post("/token",response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependancy):
    user=authenticate_user(db,form_data.username,form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    access_token = create_access_token(user.username,user.id, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.username,user.id, expires_delta=refresh_token_expires)

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)], db: db_dependancy):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("id")
        if username is None or user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user