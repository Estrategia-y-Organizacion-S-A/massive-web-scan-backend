from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List
import aiohttp
import asyncio
import json
from scanner import AsyncWebScanner

app = FastAPI(title="CMS Malware Scanner Batch API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class BatchRequest(BaseModel):
    urls: List[str]

@app.post("/api/scan/batch")
async def scan_batch(request: BatchRequest):
    urls = [u.strip() for u in request.urls if u.strip()]
    
    async def generate_responses():
        # Evento de inicio
        yield json.dumps({"event": "start", "total": len(urls)}) + "\n"
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in urls:
                if not url.startswith("http"):
                    url = "https://" + url
                scanner = AsyncWebScanner(url)
                tasks.append(scanner.run_passive_scan(session))
            
            # Emitir a medida que completan
            completed_count = 0
            for completed_task in asyncio.as_completed(tasks):
                result = await completed_task
                completed_count += 1
                yield json.dumps({
                    "event": "result", 
                    "completed": completed_count,
                    "total": len(urls),
                    "data": result
                }) + "\n"
                
        yield json.dumps({"event": "done"}) + "\n"

    return StreamingResponse(generate_responses(), media_type="application/x-ndjson")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
