from fastapi import Depends, HTTPException, APIRouter, Body
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from schemas.users import UserCreate, UsernameUpdate, User,UserLogin
from models.users import User as ModelUser
from dependencies import get_db
from utils.jwt import JWTHandler
from schemas.jwt import JWTResponsePayload,JWTPayload
from typing import List

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post("/users/", response_model=User)
async   def create_user(user_create: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(ModelUser).filter(ModelUser.username == user_create.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already exists")
    hashed_password = pwd_context.hash(user_create.password)
    new_user = ModelUser(username=user_create.username, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.delete("/users/", response_model=JWTResponsePayload)
async def delete_user(db: Session = Depends(get_db),
                      token_data: JWTPayload = Depends(JWTHandler.verify_token)):
    user_username = token_data.username
    db_user = db.query(ModelUser).filter(ModelUser.username == user_username).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return {"detail": "User deleted successfully"}

@router.put("/users/", response_model=JWTResponsePayload)
async def update_username(db: Session = Depends(get_db),
                          data: UsernameUpdate = Body(),
                          token_data: JWTPayload = Depends(JWTHandler.verify_token)):

    user_name = token_data.username
    db_user = db.query(ModelUser).filter(ModelUser.username == user_name).first()

    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if db.query(ModelUser).filter(ModelUser.username == data.new_username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    
    db_user.username = data.new_username
    db.commit()
    db.refresh(db_user)

    new_token_response = JWTHandler.generate(username=data.new_username)

    return new_token_response


@router.post("/login/", response_model=JWTResponsePayload)
async def login(user_login: UserLogin, db: Session = Depends(get_db)) -> JWTResponsePayload:
    db_user = db.query(ModelUser).filter(ModelUser.username == user_login.username).first()

    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not pwd_context.verify(user_login.password, db_user.password):
        raise HTTPException(status_code=401, detail="Incorrect password")
    
    token_response = JWTHandler.generate(username=user_login.username)

    return token_response

@router.get("/users/", response_model=List[User])
async def read_all_usernames(db: Session = Depends(get_db),
                             token_data: JWTPayload = Depends(JWTHandler.verify_token)):
    db_users = db.query(ModelUser).all()
    if not db_users:
        raise HTTPException(status_code=404, detail="No users found")
    return db_users


   

