import argparse
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apkspider.downloader import download_apk, download_from_url
from apkspider.pipeline import analyze_uploaded_apk
from apkspider.scan_persistence import persist_scan
from apkspider.scan_store import ScanStore
from apkspider.utils import print_banner

WORK_DIR = os.getcwd()


def is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"}


def _scan(args: argparse.Namespace) -> None:
    if not args.target and not args.apk:
        raise SystemExit("Provide a package name/URL or use --apk for a local file.")

    package_name = ""
    output_dir = args.output

    if args.apk:
        package_name = os.path.splitext(os.path.basename(args.apk))[0]
        output_dir = output_dir or os.path.join(WORK_DIR, package_name)
        apk_path = args.apk
    elif is_url(args.target):
        package_name = os.path.splitext(os.path.basename(urlparse(args.target).path))[0]
        output_dir = output_dir or os.path.join(WORK_DIR, package_name or "apkspider_output")
        apk_path = download_from_url(args.target, output_dir)
    else:
        package_name = args.target
        output_dir = output_dir or os.path.join(WORK_DIR, package_name)
        apk_path = download_apk(package_name, use_playwright_fallback=args.playwright_fallback)

    if not apk_path:
        print("[!] Failed to acquire APK.")
        return

    report_dir = analyze_uploaded_apk(
        apk_path,
        output_dir,
        package_name=package_name,
    )
    if not report_dir:
        print("[!] Failed to analyze APK.")
        return

    if args.save_db:
        db_path = args.save_db
        scan_store = ScanStore(db_path)
        decompiled_dir = os.path.join(output_dir, "main_apk_decompiled")
        persist_scan(report_dir, apk_path, decompiled_dir, scan_store)
        print(f"[✓] Scan saved to {db_path}")


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    os.environ.setdefault("SCAN_DB_PATH", args.db)
    uvicorn.run("api.app.main:app", host=args.host, port=args.port, reload=False)


def main() -> None:
    print_banner()

    if len(sys.argv) > 1 and sys.argv[1] in {"scan", "serve"}:
        parser = argparse.ArgumentParser(description="APKSPIDER - Automated APK Extraction & Analysis Tool")
        subparsers = parser.add_subparsers(dest="command", required=True)

        scan_parser = subparsers.add_parser("scan", help="Scan an APK/XAPK")
        scan_parser.add_argument("target", nargs="?", help="Package name or direct APK URL")
        scan_parser.add_argument("--apk", help="Path to a local APK/XAPK file")
        scan_parser.add_argument("--output", help="Output directory for reports")
        scan_parser.add_argument("--save-db", help="Path to SQLite DB for scan results")
        scan_parser.add_argument(
            "--playwright-fallback",
            action="store_true",
            help="Allow Playwright as a last-resort APK downloader",
        )
        scan_parser.set_defaults(func=_scan)

        serve_parser = subparsers.add_parser("serve", help="Serve the dashboard UI/API")
        serve_parser.add_argument("--host", default="0.0.0.0")
        serve_parser.add_argument("--port", type=int, default=8080)
        serve_parser.add_argument("--db", default=os.path.join(WORK_DIR, "scan_results.db"))
        serve_parser.set_defaults(func=_serve)

        args = parser.parse_args()
        args.func(args)
        return

    parser = argparse.ArgumentParser(description="APKSPIDER - Automated APK Extraction & Analysis Tool")
    parser.add_argument("target", nargs="?", help="Package name or direct APK URL")
    parser.add_argument("--apk", help="Path to a local APK/XAPK file")
    parser.add_argument("--output", help="Output directory for reports")
    parser.add_argument(
        "--playwright-fallback",
        action="store_true",
        help="Allow Playwright as a last-resort APK downloader",
    )

    args = parser.parse_args()
    _scan(args)


if __name__ == "__main__":
    main()
