import asyncio
import aiohttp
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from database import SessionLocal, Website
from scanner import AsyncWebScanner
import json
import urllib.parse
import platform

scheduler = AsyncIOScheduler()


async def async_ping(url):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
            
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        process = await asyncio.create_subprocess_exec(
            'ping', param, '1', hostname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        return process.returncode == 0
    except Exception:
        return False

async def check_single_uptime(session, website):
    http_up = False
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with session.get(website.url, timeout=10, headers=headers, allow_redirects=True, ssl=False) as response:
            http_up = response.status < 500
    except Exception:
        pass
        
    # Si falla por HTTP, intentamos un ping tradicional (ICMP)
    if not http_up:
        ping_up = await async_ping(website.url)
        website.is_up = ping_up
    else:
        website.is_up = True
    
    website.last_uptime_check = datetime.utcnow()

async def check_uptimes():
    print(f"[{datetime.utcnow()}] Running 5-min uptime check...")
    db = SessionLocal()
    try:
        websites = db.query(Website).all()
        async with aiohttp.ClientSession() as session:
            tasks = [check_single_uptime(session, w) for w in websites]
            await asyncio.gather(*tasks)
            db.commit()
    finally:
        db.close()
    print(f"[{datetime.utcnow()}] Uptime check completed.")

async def scan_single_website(session, website):
    scanner = AsyncWebScanner(website.url)
    result = await scanner.run_passive_scan(session)
    website.last_scan_result = json.dumps(result)

async def weekly_scans():
    print(f"[{datetime.utcnow()}] Running weekly full scan...")
    db = SessionLocal()
    try:
        websites = db.query(Website).all()
        async with aiohttp.ClientSession() as session:
            tasks = [scan_single_website(session, w) for w in websites]
            await asyncio.gather(*tasks)
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
