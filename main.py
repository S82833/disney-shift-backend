import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Field, SQLModel, create_engine, Session, select
from datetime import date, time
from typing import List, Optional

# --- MODELO DE DATOS ---
class Shift(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    type: str 
    location: str 
    shift_date: date
    start_time: time
    end_time: time
    posted_by: str

# --- CONFIGURACIÓN DE BASE DE DATOS ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:zTHpnwTbgzcgpIrQVOiHIPhvjvmyXbCB@gondola.proxy.rlwy.net:51669/railway")

# Fix para compatibilidad de SQLAlchemy con Postgres
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Todo lo que pongas ANTES del 'yield' se ejecuta al ARRANCAR
    create_db_and_tables()
    print("Base de datos conectada y tablas creadas")
    
    yield
    
    print("Limpiando recursos al cerrar...")

# --- INICIALIZACIÓN DE APP CON LIFESPAN ---
app = FastAPI(
    title="Disney Shift Exchange API",
    lifespan=lifespan 
)

# Configuración de CORS para que tu React pueda hablar con este Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependencia para la sesión de DB
def get_session():
    with Session(engine) as session:
        yield session

# --- ENDPOINTS ---

@app.get("/")
def home():
    return {"message": "Disney Shift Exchange API is running!"}

@app.post("/shifts/", response_model=Shift)
def create_shift(shift: Shift, session: Session = Depends(get_session)):
    session.add(shift)
    session.commit()
    session.refresh(shift)
    return shift

@app.get("/shifts/", response_model=List[Shift])
def read_shifts(session: Session = Depends(get_session)):
    # Los traemos ordenados por fecha para que sea más útil
    statement = select(Shift).order_by(Shift.shift_date)
    shifts = session.exec(statement).all()
    return shifts

@app.delete("/shifts/{shift_id}")
def delete_shift(shift_id: int, session: Session = Depends(get_session)):
    shift = session.get(Shift, shift_id)
    if not shift:
        raise HTTPException(status_code=404, detail="Shift no encontrado")
    session.delete(shift)
    session.commit()
    return {"ok": True}

@app.put("/shifts/{shift_id}", response_model=Shift)
def update_shift(shift_id: int, updated_data: Shift, session: Session = Depends(get_session)):
    db_shift = session.get(Shift, shift_id)
    if not db_shift:
        raise HTTPException(status_code=404, detail="Shift not found")
    
    # Update only the fields that can change
    shift_data = updated_data.model_dump(exclude_unset=True)
    for key, value in shift_data.items():
        setattr(db_shift, key, value)
    
    session.add(db_shift)
    session.commit()
    session.refresh(db_shift)
    return db_shift