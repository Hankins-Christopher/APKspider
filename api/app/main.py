import os
import hashlib
import json
import time
import uuid
from datetime import datetime
from typing import Dict, Optional, Set

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.app.auth import basic_auth
from api.app.config import settings
from api.app.dashboard import router as dashboard_router
from api.app.logging_utils import sanitize_log_lines
from api.app.store import JobStore
from api.app.worker import enqueue_job
from security import (
    generate_safe_filename,
    is_safe_client_filename,
    safe_zip_directory,
    validate_apk_structure,
    validate_xapk_structure,
)

store = JobStore()
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="APKspider API", version="1.0")
app.state.limiter = limiter
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


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
app.include_router(dashboard_router)


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: str
    created_at: str
    updated_at: str
    error_message: Optional[str]
    scan_id: Optional[int]


def _ensure_dirs() -> dict:
    base = settings.app_data_dir
    uploads = os.path.join(base, "uploads")
    chunks = os.path.join(base, "chunked_uploads")
    reports = os.path.join(base, "reports")
    logs = os.path.join(base, "logs")
    work = os.path.join(base, "work")
    for path in (uploads, chunks, reports, logs, work):
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o700)
    return {"uploads": uploads, "chunks": chunks, "reports": reports, "logs": logs, "work": work}


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


class UploadInitRequest(BaseModel):
    filename: str
    total_size: int
    total_chunks: Optional[int] = None
    expected_sha256: Optional[str] = None


@app.post("/v1/jobs")
@limiter.limit("5/minute")
async def create_job(
    request: Request,
    file: UploadFile = File(...),
    _: None = Depends(basic_auth),
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


def _cleanup_expired_uploads(chunks_dir: str) -> None:
    now = time.time()
    ttl = settings.upload_session_ttl_seconds
    for entry in os.listdir(chunks_dir):
        session_dir = os.path.join(chunks_dir, entry)
        manifest_path = os.path.join(session_dir, "manifest.json")
        if not os.path.isdir(session_dir) or not os.path.exists(manifest_path):
            continue
        try:
            with open(manifest_path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
            created_at = manifest.get("created_at", 0)
        except (OSError, json.JSONDecodeError):
            continue
        if now - created_at > ttl:
            for filename in os.listdir(session_dir):
                try:
                    os.remove(os.path.join(session_dir, filename))
                except OSError:
                    pass
            try:
                os.rmdir(session_dir)
            except OSError:
                pass


def _load_manifest(session_dir: str) -> Dict:
    manifest_path = os.path.join(session_dir, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _save_manifest(session_dir: str, manifest: Dict) -> None:
    manifest_path = os.path.join(session_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle)


@app.post("/v1/upload/init")
async def upload_init(payload: UploadInitRequest, _: None = Depends(basic_auth)):
    if not payload.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    if ".." in payload.filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if payload.total_size > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large")
    chunk_size = settings.upload_chunk_bytes
    total_chunks = payload.total_chunks or int((payload.total_size + chunk_size - 1) / chunk_size)
    if total_chunks < 1:
        raise HTTPException(status_code=400, detail="total_chunks must be >= 1")

    dirs = _ensure_dirs()
    _cleanup_expired_uploads(dirs["chunks"])

    upload_id = uuid.uuid4().hex
    session_dir = os.path.join(dirs["chunks"], upload_id)
    os.makedirs(session_dir, exist_ok=True)
    os.chmod(session_dir, 0o700)

    manifest = {
        "filename": payload.filename,
        "total_size": payload.total_size,
        "total_chunks": total_chunks,
        "expected_sha256": payload.expected_sha256 or "",
        "received": [],
        "created_at": time.time(),
    }
    _save_manifest(session_dir, manifest)
    return {"upload_id": upload_id, "chunk_size": chunk_size, "total_chunks": total_chunks}


@app.post("/v1/upload/chunk")
async def upload_chunk(
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    file: UploadFile = File(...),
    _: None = Depends(basic_auth),
):
    dirs = _ensure_dirs()
    session_dir = os.path.join(dirs["chunks"], upload_id)
    manifest_path = os.path.join(session_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        raise HTTPException(status_code=404, detail="Upload session not found")

    manifest = _load_manifest(session_dir)
    total_chunks = manifest.get("total_chunks", 0)
    if chunk_index < 0 or chunk_index >= total_chunks:
        raise HTTPException(status_code=400, detail="Invalid chunk index")

    chunk_path = os.path.join(session_dir, f"chunk_{chunk_index}.part")
    size = 0
    with open(chunk_path, "wb") as handle:
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > settings.upload_chunk_bytes * 2:
                raise HTTPException(status_code=400, detail="Chunk too large")
            handle.write(chunk)
    os.chmod(chunk_path, 0o600)

    received: Set[int] = set(manifest.get("received", []))
    received.add(int(chunk_index))
    manifest["received"] = sorted(received)
    _save_manifest(session_dir, manifest)

    return {"status": "ok", "received": len(received), "total_chunks": total_chunks}


@app.post("/v1/upload/finish")
async def upload_finish(payload: Dict[str, str], _: None = Depends(basic_auth)):
    upload_id = payload.get("upload_id", "")
    if not upload_id:
        raise HTTPException(status_code=400, detail="Missing upload_id")
    dirs = _ensure_dirs()
    session_dir = os.path.join(dirs["chunks"], upload_id)
    manifest_path = os.path.join(session_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        raise HTTPException(status_code=404, detail="Upload session not found")

    manifest = _load_manifest(session_dir)
    total_chunks = manifest.get("total_chunks", 0)
    received = set(manifest.get("received", []))
    missing = [idx for idx in range(total_chunks) if idx not in received]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing chunks: {missing[:5]}")

    filename = manifest.get("filename", "")
    if not filename:
        raise HTTPException(status_code=400, detail="Invalid upload metadata")
    if not is_safe_client_filename(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    suffix = ".apk" if filename.lower().endswith(".apk") else ".xapk"
    safe_name = generate_safe_filename(suffix)
    dest_path = os.path.join(dirs["uploads"], safe_name)
    size = 0
    digest = hashlib.sha256()
    with open(dest_path, "wb") as handle:
        for index in range(total_chunks):
            chunk_path = os.path.join(session_dir, f"chunk_{index}.part")
            with open(chunk_path, "rb") as chunk_handle:
                while True:
                    data = chunk_handle.read(1024 * 1024)
                    if not data:
                        break
                    size += len(data)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(status_code=413, detail="File too large")
                    digest.update(data)
                    handle.write(data)
    os.chmod(dest_path, 0o600)

    expected_sha256 = manifest.get("expected_sha256") or ""
    computed_sha256 = digest.hexdigest()
    if expected_sha256 and expected_sha256 != computed_sha256:
        raise HTTPException(status_code=400, detail="Checksum mismatch")

    _validate_upload(dest_path, filename)

    job_id = uuid.uuid4().hex
    report_dir = os.path.join(dirs["reports"], job_id)
    work_dir = os.path.join(dirs["work"], job_id)
    log_path = os.path.join(dirs["logs"], f"{job_id}.log")
    summary_path = os.path.join(report_dir, "summary.json")

    store.create(job_id, dest_path, work_dir, report_dir, summary_path, log_path)
    enqueue_job(job_id)

    for filename in os.listdir(session_dir):
        try:
            os.remove(os.path.join(session_dir, filename))
        except OSError:
            pass
    try:
        os.rmdir(session_dir)
    except OSError:
        pass

    return {"job_id": job_id, "sha256": computed_sha256}


@app.get("/v1/jobs/{job_id}", response_model=JobStatusResponse)
async def job_status(job_id: str, _: None = Depends(basic_auth)):
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
        scan_id=record.scan_id,
    )


@app.get("/v1/jobs/{job_id}/summary")
async def job_summary(job_id: str, _: None = Depends(basic_auth)):
    try:
        record = store.get(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    if not os.path.exists(record.summary_path):
        raise HTTPException(status_code=404, detail="Summary not ready")
    return FileResponse(record.summary_path, media_type="application/json")


@app.get("/v1/jobs/{job_id}/report.zip")
async def job_report(job_id: str, _: None = Depends(basic_auth)):
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
async def job_logs(job_id: str, _: None = Depends(basic_auth)):
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
