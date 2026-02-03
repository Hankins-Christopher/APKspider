import argparse
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apkspider.downloader import download_apk, download_from_url
from apkspider.pipeline import analyze_uploaded_apk
from apkspider.utils import print_banner

WORK_DIR = os.getcwd()


def is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"}


def main() -> None:
    print_banner()

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

    if not args.target and not args.apk:
        parser.error("Provide a package name/URL or use --apk for a local file.")

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


if __name__ == "__main__":
    main()
