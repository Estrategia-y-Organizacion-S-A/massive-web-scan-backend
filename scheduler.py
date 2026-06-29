import asyncio
import aiohttp
from datetime import datetime
from datetime import datetime, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from database import SessionLocal, Website, IncidentLog, PingHistory, get_db
from scanner import AsyncWebScanner
import json
import urllib.parse
import platform
import time
import os
from dotenv import load_dotenv
from sqlalchemy.orm import Session

load_dotenv()

scheduler = AsyncIOScheduler()

async def send_telegram_alert(message: str):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"Error sending Telegram alert: {e}")


async def async_ping(url):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, 0
            
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        start_time = time.time()
        process = await asyncio.create_subprocess_exec(
            'ping', param, '1', hostname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        latency = int((time.time() - start_time) * 1000)
        return process.returncode == 0, latency
    except Exception:
        return False, 0

async def check_single_uptime(website, db: Session):
    http_up = False
    latency_ms = 0
    start_time = time.time()
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with aiohttp.ClientSession() as session:
            async with session.get(website.url, timeout=45, headers=headers, allow_redirects=True, ssl=False) as response:
                http_up = response.status < 500
                if http_up:
                    latency_ms = int((time.time() - start_time) * 1000)
    except Exception:
        pass
        
    if not http_up:
        ping_up, ping_latency = await async_ping(website.url)
        new_status = ping_up
        latency_ms = ping_latency
    else:
        new_status = True
        
    if website.is_up in (True, None) and new_status is False:
        msg = "La web ha dejado de responder (Caída)"
        db.add(IncidentLog(website_id=website.id, incident_type="UPTIME_DOWN", message=msg))
        if website.alerts_enabled:
            await send_telegram_alert(f"🚨 <b>ALERTA DE CAÍDA</b>\nLa web {website.url} no responde.")
    elif website.is_up is False and new_status is True:
        msg = "La web ha vuelto a responder (Recuperada)"
        db.add(IncidentLog(website_id=website.id, incident_type="UPTIME_UP", message=msg))
        if website.alerts_enabled:
            await send_telegram_alert(f"✅ <b>WEB RECUPERADA</b>\nLa web {website.url} vuelve a estar operativa.")
        
    website.is_up = new_status
    website.last_uptime_check = datetime.now(timezone.utc)
    
    if new_status:
        db.add(PingHistory(website_id=website.id, response_time_ms=latency_ms))
    db.commit()

async def check_uptimes():
    print(f"[{datetime.now(timezone.utc)}] Running 5-min uptime check...")
    db = next(get_db())
    websites = db.query(Website).all()
    
    semaphore = asyncio.Semaphore(50)

    async def sem_check(website):
        async with semaphore:
            await check_single_uptime(website, db)

    tasks = [sem_check(w) for w in websites]
    if tasks:
        await asyncio.gather(*tasks)
    
    print(f"[{datetime.now(timezone.utc)}] Uptime check completed.")

async def scan_single_website(website, db: Session):
    scanner = AsyncWebScanner(website.url)
    async with aiohttp.ClientSession() as session:
        result = await scanner.run_passive_scan(session)
        website.last_scan_result = json.dumps(result)
        
        ssl_valid = result.get("ssl_valid")
        ssl_exp = result.get("ssl_expiration_date")
        if ssl_valid is not None:
            website.ssl_valid = ssl_valid
        if ssl_exp is not None:
            website.ssl_expiration_date = datetime.fromisoformat(ssl_exp)
            days_left = (website.ssl_expiration_date - datetime.now(timezone.utc)).days
            if 0 <= days_left <= 7 and website.alerts_enabled:
                msg = f"El certificado SSL caduca en {days_left} días."
                db.add(IncidentLog(website_id=website.id, incident_type="SSL_WARNING", message=msg))
                await send_telegram_alert(f"⚠️ <b>ALERTA SSL</b>\nLa web {website.url} caduca en {days_left} días.")
                
        if result.get("status") == "error":
            db.add(IncidentLog(website_id=website.id, incident_type="SCAN_ERROR", message=f"Error en escáner: {result.get('message')}"))
        db.commit()

async def run_full_scans():
    print(f"[{datetime.now(timezone.utc)}] Running weekly full scan...")
    db = next(get_db())
    websites = db.query(Website).all()
    
    semaphore = asyncio.Semaphore(10)

    async def sem_scan(website):
        async with semaphore:
            await scan_single_website(website, db)

    tasks = [sem_scan(w) for w in websites]
    if tasks:
        await asyncio.gather(*tasks)
        
    print(f"[{datetime.now(timezone.utc)}] Weekly scan completed.")

def start_scheduler():
    scheduler.add_job(check_uptimes, 'interval', minutes=5, id='uptime_job')
    scheduler.add_job(run_full_scans, 'cron', day_of_week='sun', hour=3, id='weekly_scan_job')
    scheduler.start()
