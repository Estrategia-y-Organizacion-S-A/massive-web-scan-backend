import asyncio
import aiohttp
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from database import SessionLocal, Website, IncidentLog
from scanner import AsyncWebScanner
import json
import urllib.parse
import platform
import time
import os
import requests
from dotenv import load_dotenv

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

async def check_single_uptime(session, website):
    http_up = False
    latency_ms = 0
    start_time = time.time()
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with session.get(website.url, timeout=45, headers=headers, allow_redirects=True, ssl=False) as response:
            http_up = response.status < 500
            if http_up:
                latency_ms = int((time.time() - start_time) * 1000)
    except Exception:
        pass
        
    # Si falla por HTTP, intentamos un ping tradicional (ICMP)
    if not http_up:
        ping_up, ping_latency = await async_ping(website.url)
        new_status = ping_up
        latency_ms = ping_latency
    else:
        new_status = True
        
    incidents = []
    if website.is_up is True and new_status is False:
        msg = "La web ha dejado de responder (Caída)"
        incidents.append(IncidentLog(website_id=website.id, incident_type="UPTIME_DOWN", message=msg))
        await send_telegram_alert(f"🚨 <b>ALERTA DE CAÍDA</b>\nLa web {website.url} no responde.")
    elif website.is_up is False and new_status is True:
        msg = "La web ha vuelto a responder (Recuperada)"
        incidents.append(IncidentLog(website_id=website.id, incident_type="UPTIME_UP", message=msg))
        await send_telegram_alert(f"✅ <b>WEB RECUPERADA</b>\nLa web {website.url} vuelve a estar operativa.")
        
    website.is_up = new_status
    website.last_uptime_check = datetime.utcnow()
    
    ping_log = None
    if new_status:
        from database import PingHistory
        ping_log = PingHistory(website_id=website.id, response_time_ms=latency_ms)
        
    return incidents, ping_log

async def check_uptimes():
    print(f"[{datetime.utcnow()}] Running 5-min uptime check...")
    db = SessionLocal()
    try:
        websites = db.query(Website).all()
        semaphore = asyncio.Semaphore(50)
        
        async def sem_task(session, w):
            async with semaphore:
                return await check_single_uptime(session, w)
                
        async with aiohttp.ClientSession() as session:
            tasks = [sem_task(session, w) for w in websites]
            results = await asyncio.gather(*tasks)
            for incidents, ping_log in results:
                if incidents:
                    db.add_all(incidents)
                if ping_log:
                    db.add(ping_log)
            db.commit()
    finally:
        db.close()
    print(f"[{datetime.utcnow()}] Uptime check completed.")

async def scan_single_website(session, website):
    scanner = AsyncWebScanner(website.url)
    result = await scanner.run_passive_scan(session)
    website.last_scan_result = json.dumps(result)
    
    incidents = []
    if result.get("status") == "error":
        incidents.append(IncidentLog(website_id=website.id, incident_type="SCAN_ERROR", message=f"Error en escáner: {result.get('message')}"))
    return incidents

async def weekly_scans():
    print(f"[{datetime.utcnow()}] Running weekly full scan...")
    db = SessionLocal()
    try:
        websites = db.query(Website).all()
        semaphore = asyncio.Semaphore(50)
        
        async def sem_task(session, w):
            async with semaphore:
                return await scan_single_website(session, w)
                
        async with aiohttp.ClientSession() as session:
            tasks = [sem_task(session, w) for w in websites]
            results = await asyncio.gather(*tasks)
            for incidents in results:
                if incidents:
                    db.add_all(incidents)
            db.commit()
    finally:
        db.close()
    print(f"[{datetime.utcnow()}] Weekly scan completed.")

def start_scheduler():
    # Uptime check every 5 minutes
    scheduler.add_job(check_uptimes, 'interval', minutes=5, id='uptime_job')
    
    # Weekly scan on Saturday at 23:59
    scheduler.add_job(
        weekly_scans,
        CronTrigger(day_of_week='sat', hour=23, minute=59),
        id='weekly_scan_job'
    )
    
    scheduler.start()
