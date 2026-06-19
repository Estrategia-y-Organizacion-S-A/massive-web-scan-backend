from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./websites.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Website(Base):
    __tablename__ = "websites"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True, nullable=False)
    is_up = Column(Boolean, default=None, nullable=True)
    last_uptime_check = Column(DateTime, default=None, nullable=True)
    last_scan_result = Column(String, default=None, nullable=True) # Stored as JSON string
    created_at = Column(DateTime, default=datetime.utcnow)

class IncidentLog(Base):
    __tablename__ = "incident_logs"

    id = Column(Integer, primary_key=True, index=True)
    website_id = Column(Integer, index=True, nullable=False)
    incident_type = Column(String, nullable=False) # e.g. "UPTIME_DOWN", "UPTIME_UP", "SCAN_ERROR"
    message = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class PingHistory(Base):
    __tablename__ = "ping_history"

    id = Column(Integer, primary_key=True, index=True)
    website_id = Column(Integer, index=True, nullable=False)
    response_time_ms = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
