from fastapi import Depends, HTTPException, APIRouter
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from schemas.users import UserCreate, UsernameUpdate, User
from models.users import User as ModelUser
from dependencies import get_db

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post("/users/", response_model=User)
async   def create_user(user_create: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(ModelUser).filter(ModelUser.email == user_create.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already exists")
    hashed_password = pwd_context.hash(user_create.password)
    new_user = ModelUser(email=user_create.email, username=user_create.username, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.delete("/users/{username}", response_model=User)
async   def delete_user(username: str, password: str, db: Session = Depends(get_db)):
    db_user = db.query(ModelUser).filter(ModelUser.username == username).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    # بررسی صحت کد هش رمز عبور با استفاده از تابع verify
    if not pwd_context.verify(password, db_user.password):
        raise HTTPException(status_code=401, detail="Incorrect password")
    db.delete(db_user)
    db.commit()
    return {"detail": "User deleted successfully"}


@router.put("/users/{user_id}", response_model=User)
async   def update_username(user_id: int, username_update: UsernameUpdate, db: Session = Depends(get_db)):
    db_user = db.query(ModelUser).filter(ModelUser.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not pwd_context.verify(username_update.password, db_user.password):
        raise HTTPException(status_code=401, detail="Incorrect password")
    if db.query(ModelUser).filter(ModelUser.username == username_update.new_username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    db_user.username = username_update.new_username
    db.commit()
    db.refresh(db_user)
    return db_user 

@router.get("/users/{user_id}", response_model=User)
async   def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(ModelUser).filter(ModelUser.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user
