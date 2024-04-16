from sqlalchemy import Column, String, Integer
from db import Base

class User(Base):
    __tablename__ = "User"

    id = Column(Integer, primary_key=True)
    username = Column(String,unique=True)
    password = Column(String)