import json
import os
import tempfile
import zipfile

from fastapi.testclient import TestClient

from api.app import main
from api.app.config import settings
from api.app.worker import run_job


def _create_minimal_apk(path: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "manifest")
        archive.writestr("classes.dex", "dex")


def test_upload_and_download_report(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        settings.app_data_dir = tmp
        settings.max_upload_bytes = 10 * 1024 * 1024
        settings.max_extracted_bytes = 10 * 1024 * 1024
        settings.max_extract_files = 100
        settings.max_extract_file_bytes = 1024 * 1024

        def _enqueue(job_id: str) -> None:
            run_job(job_id)

        def _fake_analyze(file_path: str, output_dir: str, package_name: str, **kwargs):
            report_dir = os.path.join(output_dir, "analysis_report")
            os.makedirs(report_dir, exist_ok=True)
            with open(os.path.join(report_dir, "summary.json"), "w", encoding="utf-8") as handle:
                json.dump({"target": "fixture", "total_findings": 0, "severity_counts": {}}, handle)
            return report_dir

        monkeypatch.setattr(main, "enqueue_job", _enqueue)
        monkeypatch.setattr("api.app.worker.analyze_uploaded_apk", _fake_analyze)
        client = TestClient(main.app)

        apk_path = os.path.join(tmp, "fixture.apk")
        _create_minimal_apk(apk_path)
        with open(apk_path, "rb") as handle:
            response = client.post("/v1/jobs", files={"file": ("fixture.apk", handle, "application/vnd.android.package-archive")})

        assert response.status_code == 200
        job_id = response.json()["job_id"]

        status = client.get(f"/v1/jobs/{job_id}")
        assert status.status_code == 200

        report = client.get(f"/v1/jobs/{job_id}/report.zip")
        assert report.status_code == 200
