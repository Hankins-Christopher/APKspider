import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from api.app.config import settings

_DB_LOCK = threading.Lock()


@dataclass
class JobRecord:
    job_id: str
    status: str
    progress: str
    created_at: str
    updated_at: str
    upload_path: str
    work_dir: str
    report_dir: str
    summary_path: str
    log_path: str
    error_message: str


def _db_path() -> str:
    os.makedirs(settings.app_data_dir, exist_ok=True)
    return os.path.join(settings.app_data_dir, "jobs.db")


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(_db_path(), check_same_thread=False)


def init_db() -> None:
    with _DB_LOCK:
        conn = _connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    progress TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    upload_path TEXT NOT NULL,
                    work_dir TEXT NOT NULL,
                    report_dir TEXT NOT NULL,
                    summary_path TEXT NOT NULL,
                    log_path TEXT NOT NULL,
                    error_message TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


class JobStore:
    def __init__(self) -> None:
        init_db()

    def create(self, job_id: str, upload_path: str, work_dir: str, report_dir: str, summary_path: str, log_path: str) -> JobRecord:
        created_at = _now()
        with _DB_LOCK:
            conn = _connect()
            try:
                conn.execute(
                    """
                    INSERT INTO jobs (job_id, status, progress, created_at, updated_at, upload_path, work_dir, report_dir, summary_path, log_path, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job_id,
                        "queued",
                        "uploaded",
                        created_at,
                        created_at,
                        upload_path,
                        work_dir,
                        report_dir,
                        summary_path,
                        log_path,
                        "",
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        return self.get(job_id)

    def update(self, job_id: str, status: Optional[str] = None, progress: Optional[str] = None, error_message: Optional[str] = None) -> JobRecord:
        with _DB_LOCK:
            conn = _connect()
            try:
                record = self.get(job_id)
                new_status = status or record.status
                new_progress = progress or record.progress
                new_error = error_message if error_message is not None else record.error_message
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = ?, progress = ?, updated_at = ?, error_message = ?
                    WHERE job_id = ?
                    """,
                    (new_status, new_progress, _now(), new_error, job_id),
                )
                conn.commit()
            finally:
                conn.close()
        return self.get(job_id)

    def get(self, job_id: str) -> JobRecord:
        with _DB_LOCK:
            conn = _connect()
            try:
                row = conn.execute(
                    """
                    SELECT job_id, status, progress, created_at, updated_at, upload_path, work_dir, report_dir, summary_path, log_path, error_message
                    FROM jobs WHERE job_id = ?
                    """,
                    (job_id,),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            raise KeyError(job_id)
        return JobRecord(*row)
