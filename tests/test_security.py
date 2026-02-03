import io
import os
import tempfile
import time
import zipfile

import pytest
from starlette.datastructures import UploadFile

from api.app import main
from api.app import worker
from api.app.config import settings
from api.app.store import JobStore
from apkspider.security import (
    is_safe_client_filename,
    safe_extract_zip,
    validate_apk_structure,
    validate_xapk_structure,
)


def _create_minimal_apk(path: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "manifest")
        archive.writestr("classes.dex", "dex")


def test_filename_validation_rejects_unicode_tricks():
    assert not is_safe_client_filename("..\\evil.apk")
    assert not is_safe_client_filename("..\/evil.apk")
    assert not is_safe_client_filename("bad\x00name.apk")


def test_validate_apk_structure_rejects_fake():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "fake.apk")
        with open(path, "wb") as handle:
            handle.write(b"notzip")
        valid, _ = validate_apk_structure(path)
        assert not valid


def test_validate_apk_structure_rejects_missing_manifest():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "fake.apk")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("classes.dex", "dex")
        valid, _ = validate_apk_structure(path)
        assert not valid


def test_validate_xapk_structure_requires_apk_entries():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "fake.xapk")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", "{}")
        valid, _ = validate_xapk_structure(path)
        assert not valid


def test_save_upload_rejects_huge_file(tmp_path):
    fake = io.BytesIO(b"0" * 1024)
    upload = UploadFile(filename="sample.apk", file=fake)
    with pytest.raises(Exception):
        main._save_upload(upload, limit_bytes=1, upload_dir=str(tmp_path))


def test_safe_extract_blocks_zip_slip():
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "bad.zip")
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("../evil.txt", "oops")
        with pytest.raises(ValueError):
            safe_extract_zip(zip_path, os.path.join(tmp, "out"), 1024, 10, 1024)


def test_safe_extract_blocks_symlink():
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "symlink.zip")
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr(info, "target")
        with pytest.raises(ValueError):
            safe_extract_zip(zip_path, os.path.join(tmp, "out"), 1024, 10, 1024)


def test_job_timeout_behavior(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        apk_path = os.path.join(tmp, "app.apk")
        _create_minimal_apk(apk_path)
        settings.job_timeout_seconds = 1
        settings.app_data_dir = tmp
        store = JobStore()
        job_id = "timeoutjob"
        store.create(
            job_id,
            upload_path=apk_path,
            work_dir=os.path.join(tmp, "work"),
            report_dir=os.path.join(tmp, "reports"),
            summary_path=os.path.join(tmp, "reports", "summary.json"),
            log_path=os.path.join(tmp, "logs", "job.log"),
        )

        def slow_analyze(*args, **kwargs):
            time.sleep(2)
            return None

        monkeypatch.setattr(worker, "analyze_uploaded_apk", slow_analyze)
        worker.run_job(job_id)
        updated = store.get(job_id)
        assert updated.status == "failed"
