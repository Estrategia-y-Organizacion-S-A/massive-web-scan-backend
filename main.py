from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import json
from sqlalchemy.orm import Session
import aiohttp
import asyncio

from database import init_db, get_db, Website
from scheduler import start_scheduler
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

    class Config:
        from_attributes = True

@app.post("/api/websites", response_model=List[WebsiteResponse])
def add_websites(request: BatchRequest, db: Session = Depends(get_db)):
    added_websites = []
    for url in request.urls:
        url = url.strip()
        if not url:
            continue
        if not url.startswith("http"):
            url = "https://" + url
            
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
def get_websites(db: Session = Depends(get_db)):
    return db.query(Website).all()

@app.delete("/api/websites/{website_id}")
def delete_website(website_id: int, db: Session = Depends(get_db)):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    db.delete(website)
    db.commit()
    return {"message": "Website deleted"}

@app.post("/api/websites/{website_id}/scan", response_model=WebsiteResponse)
async def scan_website_now(website_id: int, db: Session = Depends(get_db)):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
        
    async with aiohttp.ClientSession() as session:
        scanner = AsyncWebScanner(website.url)
        result = await scanner.run_passive_scan(session)
        website.last_scan_result = json.dumps(result)
        db.commit()
        db.refresh(website)
        
    return website


@app.post("/api/websites/scan-all")
async def scan_all_now(db: Session = Depends(get_db)):
    websites = db.query(Website).all()
    if not websites:
        return {"message": "No websites to scan"}
        
    async def scan_single(session, w):
        scanner = AsyncWebScanner(w.url)
        res = await scanner.run_passive_scan(session)
        w.last_scan_result = json.dumps(res)

    async with aiohttp.ClientSession() as session:
        tasks = [scan_single(session, w) for w in websites]
        await asyncio.gather(*tasks)
        
    db.commit()
    return {"message": f"Scanned {len(websites)} websites"}

class WebsiteUpdate(BaseModel):
    url: str

@app.put("/api/websites/{website_id}", response_model=WebsiteResponse)
def update_website(website_id: int, request: WebsiteUpdate, db: Session = Depends(get_db)):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
        
    new_url = request.url.strip()
    if not new_url.startswith("http"):
        new_url = "https://" + new_url
        
    website.url = new_url
    website.is_up = None # Reset status
    website.last_uptime_check = None
    website.last_scan_result = None # Clear old scan data because URL changed
    db.commit()
    db.refresh(website)
    return website

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
