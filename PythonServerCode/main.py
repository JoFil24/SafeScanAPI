from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from scanner import start_scan, load_job
from config import API_KEY, ALLOWED_IPS

app = FastAPI()

class ScanRequest(BaseModel):
    target: str

@app.middleware("http")
async def guard(request: Request, call_next):
    client_ip = request.client.host
    if client_ip not in ALLOWED_IPS:
        raise HTTPException(status_code=403, detail="Forbidden")
    key = request.headers.get("X-API-Key")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return await call_next(request)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan")
def create_scan(body: ScanRequest):
    job_id = start_scan(body.target)
    return {"job_id": job_id, "status": "started"}

@app.get("/scan/{job_id}")
def get_scan(job_id: str):
    job = load_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job
