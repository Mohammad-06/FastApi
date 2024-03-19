# from db import Base
from sqlalchemy import Column, String, Integer
from db import Base

class User(Base):
    __tablename__ = "User"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    username = Column(String)
    password = Column(String)