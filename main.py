from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

SQLALCHEMY_DATABASE_URL = "postgresql://postgres:12345@localhost/chat_app"
Base = declarative_base()

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

SECRET_KEY = "hassan"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_online = Column(Boolean, default=False)

    answer1_hashed = Column(String, nullable=False)
    answer2_hashed = Column(String, nullable=False)
    answer3_hashed = Column(String, nullable=False)
    answer4_hashed = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str
    answer1: str
    answer2: str
    answer3: str
    answer4: str

class UserOut(UserBase):
    id: int
    is_online: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        hashed_password = get_password_hash(user.password)
        new_user = User(
            username=user.username,
            email=user.email,
            hashed_password=hashed_password,
            is_online=False,
            answer1_hashed=get_password_hash(user.answer1),
            answer2_hashed=get_password_hash(user.answer2),
            answer3_hashed=get_password_hash(user.answer3),
            answer4_hashed=get_password_hash(user.answer4)
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {
            "message": "User registered successfully",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "is_online": new_user.is_online
            }
        }
    except Exception as e:
        print("Error during registration:", str(e))
        raise HTTPException(status_code=500, detail="Internal Server Error")

class ResetPasswordRequest(BaseModel):
    username: str
    answers: list[str]
    new_password: str

@app.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    hashed_answers = [user.answer1_hashed, user.answer2_hashed, user.answer3_hashed, user.answer4_hashed]

    for provided, actual in zip(request.answers, hashed_answers):
        if not verify_password(provided, actual):
            raise HTTPException(status_code=403, detail="Incorrect security answer")

    user.hashed_password = get_password_hash(request.new_password)
    db.commit()
    return {"message": "Password reset successfully"}

@app.get("/security-question/{username}")
def get_security_question(username: str):
    # The questions are supposed to come from the frontend, so this just returns a placeholder
    return {
        "questions": [
            "What is your favorite color?",
            "What is your pet's name?",
            "What is your birthplace?",
            "What is your mother's maiden name?"
        ]
    }

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/token", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}
