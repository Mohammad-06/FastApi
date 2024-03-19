from pydantic import BaseModel


class UserBase(BaseModel):
    username: str
    password: str
    email: str
class UserCreate(UserBase):
    ...
class UsernameUpdate(BaseModel):
    old_username: str
    new_username: str
    password: str 
class User(UserBase):
    id: int

    class Config:
        from_attributes = True

