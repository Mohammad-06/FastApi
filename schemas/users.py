from pydantic import BaseModel


class UserBase(BaseModel):
    username: str
class UserCreate(UserBase):
    password: str
class UsernameUpdate(BaseModel): 
    new_username: str
class UserLogin(BaseModel):
    username : str
    password : str
class User(UserBase):
    id: int

    class Config:
        from_attributes = True

