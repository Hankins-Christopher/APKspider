import argparse
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apkspider.analysis import run_analysis
from apkspider.decompiler import decompile_apk
from apkspider.downloader import download_apk, download_from_url
from apkspider.extractor import extract_apk_from_xapk
from apkspider.utils import print_banner

WORK_DIR = os.getcwd()


def is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"}


def select_main_apk(apks, package_name: str):
    if not apks:
        return None
    for apk in apks:
        if package_name and package_name in os.path.basename(apk):
            return apk
    return apks[0]


def resolve_apk_from_local(path: str, output_dir: str):
    if not os.path.isfile(path):
        print(f"[!] APK path does not exist: {path}")
        return None
    if path.endswith(".apk"):
        return path
    extracted = extract_apk_from_xapk(path, output_dir)
    return select_main_apk(extracted, "")


def main():
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
        apk_path = resolve_apk_from_local(args.apk, output_dir)
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

    print(f"[~] Attempting to extract APK(s) from: {apk_path}")
    extracted_apks = extract_apk_from_xapk(apk_path, output_dir)
    if not extracted_apks:
        extracted_apks = [apk_path]

    main_apk = select_main_apk(extracted_apks, package_name)
    if not main_apk:
        print("[!] Could not find a valid main APK.")
        return

    print(f"[✓] Main APK selected: {main_apk}")
    decompiled_main = decompile_apk(main_apk, os.path.join(output_dir, "main_apk_decompiled"))
    if not decompiled_main:
        print("[!] Failed to decompile APK.")
        return

    print("[🔍] Running deterministic sensitive file analysis...")
    report_dir = os.path.join(output_dir, "analysis_report")
    run_analysis(decompiled_main, report_dir, target=package_name or main_apk)


if __name__ == "__main__":
    main()
