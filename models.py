
from sqlalchemy import Column,String,Integer

from database import Base


class User(Base):
    __tablename__='users'
    
    id=Column(Integer,primary_key=True,index=True)
    username=Column(String(100),unique=True)
    email=Column(String(200),nullable=False)
    age=Column(Integer,nullable=False)
    password = Column(String(255))

    
    
    