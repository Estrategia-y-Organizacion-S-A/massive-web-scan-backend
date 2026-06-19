from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime
import json
from sqlalchemy.orm import Session
import aiohttp
import asyncio

from fastapi.responses import Response
import csv
import io
import jwt
import os
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-1234")
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

from database import engine, Base, init_db, get_db, Website, IncidentLog, PingHistory
from scheduler import start_scheduler, check_single_uptime, scan_single_website
from scanner import AsyncWebScanner

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializar Base de datos
    init_db()
    # Iniciar el scheduler
    start_scheduler()
    yield
    # Limpieza si es necesario al cerrar

app = FastAPI(title="CMS Malware Scanner Batch API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class BatchRequest(BaseModel):
    urls: List[str]

class WebsiteResponse(BaseModel):
    id: int
    url: str
    is_up: Optional[bool]
    last_uptime_check: Optional[datetime]
    last_scan_result: Optional[str]

    model_config = ConfigDict(from_attributes=True)

class IncidentResponse(BaseModel):
    id: int
    website_id: int
    incident_type: str
    message: str
    created_at: datetime
    website_url: Optional[str] = None # Added for convenience in UI

    model_config = ConfigDict(from_attributes=True)

def normalize_url(url: str) -> str:
    url = url.strip()
    if url and not url.startswith("http"):
        url = "https://" + url
    return url

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    admin_user = os.getenv("ADMIN_USER", "admin")
    admin_pass = os.getenv("ADMIN_PASS", "admin123")
    
    if form_data.username == admin_user and form_data.password == admin_pass:
        token = jwt.encode({"sub": admin_user}, SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Incorrect username or password")

@app.post("/api/websites", response_model=List[WebsiteResponse])
def add_websites(request: BatchRequest, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    added_websites = []
    for url in request.urls:
        url = normalize_url(url)
        if not url:
            continue
            
        existing = db.query(Website).filter(Website.url == url).first()
        if not existing:
            new_website = Website(url=url)
            db.add(new_website)
            db.commit()
            db.refresh(new_website)
            added_websites.append(new_website)
        else:
            added_websites.append(existing)
            
    return added_websites

@app.get("/api/websites", response_model=List[WebsiteResponse])
def get_websites(db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    return db.query(Website).all()

@app.delete("/api/websites/{website_id}")
def delete_website(website_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    db.delete(website)
    db.commit()
    return {"message": "Website deleted"}

@app.get("/api/incidents", response_model=List[IncidentResponse])
def get_incidents(db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    # Join with Website to get the URL
    results = db.query(IncidentLog, Website.url).outerjoin(Website, IncidentLog.website_id == Website.id).order_by(IncidentLog.created_at.desc()).limit(100).all()
    incidents = []
    for log, url in results:
        inc = IncidentResponse.model_validate(log)
        inc.website_url = url or "Eliminada"
        incidents.append(inc)
    return incidents

@app.post("/api/websites/{website_id}/scan", response_model=WebsiteResponse)
async def scan_website_now(website_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
        
    async with aiohttp.ClientSession() as session:
        uptime_incidents, ping_log = await check_single_uptime(session, website)
        scan_incidents = await scan_single_website(session, website)
        all_incidents = uptime_incidents + scan_incidents
        
        if ping_log:
            db.add(ping_log)
        if all_incidents:
            db.add_all(all_incidents)
        db.commit()
        db.refresh(website)
        
    return website


@app.post("/api/websites/scan-all")
async def scan_all_now(db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    websites = db.query(Website).all()
    if not websites:
        return {"message": "No websites to scan"}

    semaphore = asyncio.Semaphore(50)
    
    async def sem_task(session, w):
        async with semaphore:
            uptime_incidents, ping_log = await check_single_uptime(session, w)
            scan_incidents = await scan_single_website(session, w)
            
            if ping_log:
                db.add(ping_log)
            return uptime_incidents + scan_incidents

    async with aiohttp.ClientSession() as session:
        tasks = [sem_task(session, w) for w in websites]
        results = await asyncio.gather(*tasks)
        for incidents in results:
            if incidents:
                db.add_all(incidents)
        
    db.commit()
    return {"message": f"Scanned {len(websites)} websites"}

class UpdateUrlRequest(BaseModel):
    url: str

@app.put("/api/websites/{website_id}", response_model=WebsiteResponse)
def update_website_url(website_id: int, request: UpdateUrlRequest, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    new_url = normalize_url(request.url)
    website.url = new_url
    website.is_up = None # Reset status
    website.last_uptime_check = None
    website.last_scan_result = None # Clear old scan data because URL changed
    db.commit()
    db.refresh(website)
    return website

@app.get("/api/incidents/export")
def export_incidents(db: Session = Depends(get_db), token: str = ""):
    # Use token query param because you can't easily send Bearer header in <a href> download
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    incidents = db.query(IncidentLog).order_by(IncidentLog.created_at.desc()).all()
    websites = {w.id: w.url for w in db.query(Website).all()}
    
    output = io.StringIO()
    writer = csv.writer(output, dialect='excel')
    writer.writerow(['ID', 'Fecha', 'URL', 'Tipo de Incidente', 'Mensaje'])
    
    for inc in incidents:
        url = websites.get(inc.website_id, "Eliminada")
        writer.writerow([inc.id, inc.created_at.strftime('%Y-%m-%d %H:%M:%S'), url, inc.incident_type, inc.message])
        
    csv_content = output.getvalue()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=reportes_incidentes.csv"}
    )

@app.get("/api/websites/{website_id}/ping-history")
def get_ping_history(website_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    history = db.query(PingHistory).filter(PingHistory.website_id == website_id).order_by(PingHistory.created_at.desc()).limit(144).all() # Last 12 hours (12 * 12)
    history.reverse()
    return history

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
