import os
import bcrypt
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Field, SQLModel, create_engine, Session, select
from datetime import date, time, datetime, timedelta
from typing import List, Optional
from jose import JWTError, jwt

# --- SECURITY CONFIG ---
SECRET_KEY = os.getenv("JWT_SECRET", "disney-park-greeter-secret-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- PASSWORD HASHING (DIRECT BCRYPT) ---
def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

# --- DATA MODELS ---

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)  # New Field
    hashed_password: str

class UserCreate(SQLModel):
    """Schema for incoming registration data"""
    username: str
    email: str
    password: str

class Shift(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    type: str 
    location: str 
    shift_date: date
    start_time: time
    end_time: time
    posted_by: str

# --- DATABASE CONFIGURATION ---
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    print("Database connected and tables verified/created")
    yield

# --- APP INITIALIZATION ---
app = FastAPI(title="Disney Shift Exchange API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DEPENDENCIES ---
def get_session():
    with Session(engine) as session:
        yield session

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None:
        raise credentials_exception
    return user

# --- AUTH ENDPOINTS ---

@app.post("/register")
def register(user_data: UserCreate, session: Session = Depends(get_session)):
    # Check if username or email already exists
    existing_user = session.exec(
        select(User).where((User.username == user_data.username) | (User.email == user_data.email))
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered")

    hashed = hash_password(user_data.password)
    new_user = User(
        username=user_data.username, 
        email=user_data.email, 
        hashed_password=hashed
    )
    session.add(new_user)
    session.commit()
    return {"message": "User created successfully"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + access_token_expires
    to_encode = {"exp": expire, "sub": user.username}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"access_token": encoded_jwt, "token_type": "bearer"}

# --- SHIFT ENDPOINTS (PROTECTED) ---

@app.get("/")
def home():
    return {"message": "Disney Shift Exchange API is running!"}

@app.post("/shifts/", response_model=Shift)
def create_shift(shift: Shift, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    session.add(shift)
    session.commit()
    session.refresh(shift)
    return shift

@app.get("/shifts/", response_model=List[Shift])
def read_shifts(session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    statement = select(Shift).order_by(Shift.shift_date)
    shifts = session.exec(statement).all()
    return shifts

@app.delete("/shifts/{shift_id}")
def delete_shift(shift_id: int, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    shift = session.get(Shift, shift_id)
    if not shift:
        raise HTTPException(status_code=404, detail="Shift not found")
    session.delete(shift)
    session.commit()
    return {"ok": True}

@app.put("/shifts/{shift_id}", response_model=Shift)
def update_shift(shift_id: int, updated_data: Shift, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    db_shift = session.get(Shift, shift_id)
    if not db_shift:
        raise HTTPException(status_code=404, detail="Shift not found")
    
    shift_data = updated_data.model_dump(exclude_unset=True)
    for key, value in shift_data.items():
        setattr(db_shift, key, value)
    
    session.add(db_shift)
    session.commit()
    session.refresh(db_shift)
    return db_shift