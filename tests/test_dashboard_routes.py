import os
import tempfile

from fastapi.testclient import TestClient

from api.app import main
from api.app.config import settings
from apkspider.scan_store import ScanStore


def test_dashboard_routes_smoke():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "scan_results.db")
        settings.app_data_dir = tmp
        settings.scan_db_path = db_path

        store = ScanStore(db_path)
        scan_id = store.create_scan(
            filename="fixture.apk",
            sha256="deadbeef",
            package_name="com.example.app",
            version_name="1.0",
            version_code="1",
            min_sdk="21",
            target_sdk="34",
            permissions=["android.permission.INTERNET"],
            overall_risk=6.4,
        )

        client = TestClient(main.app)
        response = client.get("/dashboard")
        assert response.status_code == 200

        detail = client.get(f"/dashboard/scans/{scan_id}")
        assert detail.status_code == 200
