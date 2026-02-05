import os
import resource
import shutil
import signal
import socket
import tempfile
from contextlib import contextmanager

from redis import Redis
from rq import Queue

from api.app.config import settings
from api.app.logging_utils import sanitize_log_line
from api.app.store import JobStore
from scan_persistence import persist_scan
from scan_store import ScanStore
from pipeline import analyze_uploaded_apk
from security import validate_apk_structure, validate_xapk_structure

store = JobStore()


@contextmanager
def job_timeout(seconds: int):
    def _handler(signum, frame):
        raise TimeoutError("Job timed out")

    original = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original)


def apply_resource_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (settings.job_cpu_seconds, settings.job_cpu_seconds))
    resource.setrlimit(resource.RLIMIT_AS, (settings.job_memory_bytes, settings.job_memory_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (settings.job_fds, settings.job_fds))
    resource.setrlimit(resource.RLIMIT_NPROC, (settings.job_nproc, settings.job_nproc))


def disable_network() -> None:
    if not settings.disable_job_network:
        return

    def _blocked(*args, **kwargs):
        raise PermissionError("network disabled")

    socket.socket = _blocked  # type: ignore[assignment]


def _log(job_id: str, message: str) -> None:
    record = store.get(job_id)
    sanitized = sanitize_log_line(message)
    with open(record.log_path, "a", encoding="utf-8") as handle:
        handle.write(sanitized + "\n")


def run_job(job_id: str) -> None:
    record = store.get(job_id)
    os.makedirs(os.path.dirname(record.log_path), exist_ok=True)

    store.update(job_id, status="running", progress="validating")
    _log(job_id, "Starting validation")

    apply_resource_limits()
    disable_network()

    try:
        with job_timeout(settings.job_timeout_seconds):
            valid_apk, _ = validate_apk_structure(record.upload_path)
            valid_xapk, _ = validate_xapk_structure(record.upload_path)
            if not (valid_apk or valid_xapk):
                store.update(job_id, status="failed", progress="failed", error_message="Invalid upload")
                _log(job_id, "Upload failed validation")
                return

            store.update(job_id, progress="extracting")
            _log(job_id, "Extracting archive")

            work_root = record.work_dir
            os.makedirs(work_root, exist_ok=True)
            tempfile.tempdir = work_root
            os.umask(0o077)

            input_suffix = ".apk" if record.upload_path.endswith(".apk") else ".xapk"
            input_copy = os.path.join(work_root, f"input{input_suffix}")
            shutil.copyfile(record.upload_path, input_copy)

            store.update(job_id, progress="decompiling")
            _log(job_id, "Decompiling APK")

            store.update(job_id, progress="analyzing")
            report_dir = analyze_uploaded_apk(
                input_copy,
                work_root,
                package_name="",
                extract_limits={
                    "max_bytes": settings.max_extracted_bytes,
                    "max_files": settings.max_extract_files,
                    "per_file_max_bytes": settings.max_extract_file_bytes,
                },
                decompile_timeout=settings.job_timeout_seconds,
            )

            if not report_dir:
                store.update(job_id, status="failed", progress="failed", error_message="Analysis failed")
                _log(job_id, "Analysis failed")
                return

            store.update(job_id, progress="packaging")
            _log(job_id, "Packaging report")

            os.makedirs(record.report_dir, exist_ok=True)
            if os.path.realpath(report_dir) != os.path.realpath(record.report_dir):
                shutil.copytree(report_dir, record.report_dir, dirs_exist_ok=True)

            summary_path = os.path.join(record.report_dir, "summary.json")
            if not os.path.exists(summary_path):
                with open(summary_path, "w", encoding="utf-8") as handle:
                    handle.write("{}")

            scan_db_path = settings.scan_db_path or os.path.join(settings.app_data_dir, "scan_results.db")
            scan_store = ScanStore(scan_db_path)
            decompiled_dir = os.path.join(work_root, "main_apk_decompiled")
            scan_id = persist_scan(
                report_dir=report_dir,
                apk_path=input_copy,
                decompiled_dir=decompiled_dir,
                scan_store=scan_store,
            )

            store.update(job_id, status="complete", progress="complete", scan_id=scan_id)
            _log(job_id, "Job complete")

    except TimeoutError:
        store.update(job_id, status="failed", progress="failed", error_message="Job timed out")
        _log(job_id, "Job timed out")
    except Exception:
        store.update(job_id, status="failed", progress="failed", error_message="Job failed")
        _log(job_id, "Job failed")
    finally:
        if not settings.keep_job_dirs:
            shutil.rmtree(record.work_dir, ignore_errors=True)
            try:
                os.remove(record.upload_path)
            except OSError:
                pass


def get_queue() -> Queue:
    connection = Redis.from_url(settings.redis_url)
    return Queue("apkspider", connection=connection)


def enqueue_job(job_id: str) -> None:
    queue = get_queue()
    queue.enqueue(run_job, job_id, job_id=job_id)
