import os
import uuid
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.app.config import settings
from api.app.logging_utils import sanitize_log_lines
from api.app.store import JobStore
from api.app.worker import enqueue_job
from apkspider.security import (
    generate_safe_filename,
    is_safe_client_filename,
    safe_zip_directory,
    validate_apk_structure,
    validate_xapk_structure,
)

store = JobStore()
limiter = Limiter(key_func=get_remote_address)
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="APKspider API", version="1.0")
app.state.limiter = limiter


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"  # frontend handles full CSP
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return PlainTextResponse("rate limit exceeded", status_code=429)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.allowed_origins.split(",")],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"]
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: str
    created_at: str
    updated_at: str
    error_message: Optional[str]


def _ensure_dirs() -> dict:
    base = settings.app_data_dir
    uploads = os.path.join(base, "uploads")
    reports = os.path.join(base, "reports")
    logs = os.path.join(base, "logs")
    work = os.path.join(base, "work")
    for path in (uploads, reports, logs, work):
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o700)
    return {"uploads": uploads, "reports": reports, "logs": logs, "work": work}


def _save_upload(file: UploadFile, limit_bytes: int, upload_dir: str) -> str:
    if not is_safe_client_filename(file.filename):
        raise HTTPException(status_code=400, detail="Invalid filename")
    suffix = ".apk" if file.filename.lower().endswith(".apk") else ".xapk"
    safe_name = generate_safe_filename(suffix)
    dest_path = os.path.join(upload_dir, safe_name)
    size = 0
    with open(dest_path, "wb") as handle:
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit_bytes:
                handle.close()
                os.remove(dest_path)
                raise HTTPException(status_code=413, detail="File too large")
            handle.write(chunk)
    os.chmod(dest_path, 0o600)
    return dest_path


def _validate_upload(path: str, original_name: str) -> None:
    if not (original_name.lower().endswith(".apk") or original_name.lower().endswith(".xapk")):
        raise HTTPException(status_code=400, detail="Invalid file extension")
    valid_apk, _ = validate_apk_structure(path)
    valid_xapk, _ = validate_xapk_structure(path)
    if not (valid_apk or valid_xapk):
        raise HTTPException(status_code=400, detail="Invalid APK/XAPK content")


def _basic_auth(credentials: HTTPBasicCredentials = Depends(security)) -> None:
    if not settings.enable_basic_auth:
        return
    if not settings.basic_auth_password_hash:
        raise HTTPException(status_code=500, detail="Basic auth misconfigured")
    valid_username = credentials.username == settings.basic_auth_username
    valid_password = pwd_context.verify(credentials.password, settings.basic_auth_password_hash)
    if not (valid_username and valid_password):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/v1/jobs")
@limiter.limit("5/minute")
async def create_job(
    request: Request,
    file: UploadFile = File(...),
    _: None = Depends(_basic_auth),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    if ".." in file.filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large")

    dirs = _ensure_dirs()
    upload_path = _save_upload(file, settings.max_upload_bytes, dirs["uploads"])
    _validate_upload(upload_path, file.filename)

    job_id = uuid.uuid4().hex
    report_dir = os.path.join(dirs["reports"], job_id)
    work_dir = os.path.join(dirs["work"], job_id)
    log_path = os.path.join(dirs["logs"], f"{job_id}.log")
    summary_path = os.path.join(report_dir, "summary.json")

    store.create(job_id, upload_path, work_dir, report_dir, summary_path, log_path)
    enqueue_job(job_id)

    return {"job_id": job_id}


@app.get("/v1/jobs/{job_id}", response_model=JobStatusResponse)
async def job_status(job_id: str, _: None = Depends(_basic_auth)):
    try:
        record = store.get(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(
        job_id=record.job_id,
        status=record.status,
        progress=record.progress,
        created_at=record.created_at,
        updated_at=record.updated_at,
        error_message=record.error_message or None,
    )


@app.get("/v1/jobs/{job_id}/summary")
async def job_summary(job_id: str, _: None = Depends(_basic_auth)):
    try:
        record = store.get(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    if not os.path.exists(record.summary_path):
        raise HTTPException(status_code=404, detail="Summary not ready")
    return FileResponse(record.summary_path, media_type="application/json")


@app.get("/v1/jobs/{job_id}/report.zip")
async def job_report(job_id: str, _: None = Depends(_basic_auth)):
    try:
        record = store.get(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    if record.status != "complete":
        raise HTTPException(status_code=400, detail="Report not ready")
    report_zip = os.path.join(record.report_dir, "report.zip")
    safe_zip_directory(record.report_dir, report_zip)
    return FileResponse(report_zip, media_type="application/zip", filename="report.zip")


@app.get("/v1/jobs/{job_id}/logs")
async def job_logs(job_id: str, _: None = Depends(_basic_auth)):
    try:
        record = store.get(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    if not os.path.exists(record.log_path):
        raise HTTPException(status_code=404, detail="Logs not ready")
    with open(record.log_path, "r", encoding="utf-8") as handle:
        text = sanitize_log_lines(handle.readlines())
    return PlainTextResponse(text)


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok", "time": datetime.utcnow().isoformat() + "Z"})
