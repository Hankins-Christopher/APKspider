import hashlib
import json
import os
import tempfile
import zipfile

from fastapi.testclient import TestClient

from api.app import main
from api.app.config import settings


def _create_minimal_apk(path: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "manifest")
        archive.writestr("classes.dex", "dex")


def test_chunked_upload_happy_path(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        settings.app_data_dir = tmp
        settings.max_upload_bytes = 5 * 1024 * 1024
        settings.upload_chunk_bytes = 1024

        monkeypatch.setattr(main, "enqueue_job", lambda job_id: None)

        apk_path = os.path.join(tmp, "fixture.apk")
        _create_minimal_apk(apk_path)
        with open(apk_path, "rb") as handle:
            data = handle.read()

        client = TestClient(main.app)
        total_chunks = (len(data) + settings.upload_chunk_bytes - 1) // settings.upload_chunk_bytes
        init_response = client.post(
            "/v1/upload/init",
            json={
                "filename": "fixture.apk",
                "total_size": len(data),
                "total_chunks": total_chunks,
                "expected_sha256": hashlib.sha256(data).hexdigest(),
            },
        )
        assert init_response.status_code == 200
        upload_id = init_response.json()["upload_id"]

        for index in range(total_chunks):
            start = index * settings.upload_chunk_bytes
            end = start + settings.upload_chunk_bytes
            chunk = data[start:end]
            response = client.post(
                "/v1/upload/chunk",
                data={"upload_id": upload_id, "chunk_index": str(index)},
                files={"file": ("chunk", chunk, "application/octet-stream")},
            )
            assert response.status_code == 200

        finish_response = client.post("/v1/upload/finish", json={"upload_id": upload_id})
        assert finish_response.status_code == 200
        payload = finish_response.json()
        assert "job_id" in payload


def test_chunked_upload_missing_chunk(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        settings.app_data_dir = tmp
        settings.max_upload_bytes = 5 * 1024 * 1024
        settings.upload_chunk_bytes = 1024

        monkeypatch.setattr(main, "enqueue_job", lambda job_id: None)

        apk_path = os.path.join(tmp, "fixture.apk")
        _create_minimal_apk(apk_path)
        with open(apk_path, "rb") as handle:
            data = handle.read()

        client = TestClient(main.app)
        total_chunks = (len(data) + settings.upload_chunk_bytes - 1) // settings.upload_chunk_bytes
        init_response = client.post(
            "/v1/upload/init",
            json={
                "filename": "fixture.apk",
                "total_size": len(data),
                "total_chunks": total_chunks,
            },
        )
        assert init_response.status_code == 200
        upload_id = init_response.json()["upload_id"]

        response = client.post(
            "/v1/upload/chunk",
            data={"upload_id": upload_id, "chunk_index": "0"},
            files={"file": ("chunk", data[: settings.upload_chunk_bytes], "application/octet-stream")},
        )
        assert response.status_code == 200

        finish_response = client.post("/v1/upload/finish", json={"upload_id": upload_id})
        assert finish_response.status_code == 400
