import datetime
import hashlib
import json
import os
import re
import time
from html import unescape
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

import requests

APP_CACHE_FILE = "apks_downloaded.json"
APK_OUTPUT_DIR = "downloads"
DEFAULT_TIMEOUT = 20
RETRY_COUNT = 3
RETRY_BACKOFF = 2

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


def load_cache():
    if Path(APP_CACHE_FILE).exists():
        with open(APP_CACHE_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return {}


def save_cache(data):
    with open(APP_CACHE_FILE, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def hash_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def record_metadata(package_name, file_path, source):
    cache = load_cache()
    metadata = {
        "filename": os.path.basename(file_path),
        "path": file_path,
        "sha256": hash_file(file_path),
        "downloaded_at": datetime.datetime.now().isoformat(),
        "source": source,
    }
    cache[package_name] = metadata
    save_cache(cache)
    print(f"[INFO] Metadata recorded for {package_name}")


def request_with_retry(url, stream=False):
    last_exc = None
    for attempt in range(1, RETRY_COUNT + 1):
        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT, stream=stream)
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last_exc = exc
            sleep_for = RETRY_BACKOFF ** (attempt - 1)
            print(f"[WARN] Request failed ({attempt}/{RETRY_COUNT}): {exc}. Retrying in {sleep_for}s")
            time.sleep(sleep_for)
    raise last_exc


def download_from_url(url: str, output_dir: str) -> Optional[str]:
    parsed = urlparse(url)
    filename = os.path.basename(parsed.path) or "downloaded.apk"
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, filename)

    try:
        response = request_with_retry(url, stream=True)
        with open(file_path, "wb") as handle:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    handle.write(chunk)
        print(f"[✓] Downloaded APK to {file_path}")
        return file_path
    except requests.RequestException as exc:
        print(f"[!] Failed to download from URL: {exc}")
        return None


def find_apkpure_app_url(package_name: str) -> Optional[str]:
    search_url = f"https://apkpure.com/search?q={package_name}"
    try:
        response = request_with_retry(search_url)
    except requests.RequestException:
        return None

    matches = re_find_all(r'href="(/[^\"]+/{}[^\"]*)"'.format(re.escape(package_name)), response.text)
    for match in matches:
        if package_name in match:
            return f"https://apkpure.com{match}"
    return None


def parse_download_url(html: str, package_name: str) -> Optional[str]:
    for raw in re_find_all(r'dt-params="([^"]+)"', html):
        params_raw = unescape(raw)
        decoded = unquote(params_raw)
        params = parse_qs(decoded, keep_blank_values=True)
        if params.get("package_name", [""])[0] != package_name:
            continue
        link = params.get("link_url", [""])[0]
        if link:
            return link
    return None


def download_from_apkpure(package_name: str) -> Optional[str]:
    app_url = find_apkpure_app_url(package_name)
    if not app_url:
        print("[WARN] Unable to locate app page via HTTP search.")
        return None

    try:
        response = request_with_retry(app_url)
    except requests.RequestException as exc:
        print(f"[WARN] Failed to fetch app page: {exc}")
        return None

    download_url = parse_download_url(response.text, package_name)
    if not download_url:
        print("[WARN] Could not extract direct download URL from app page.")
        return None

    return download_from_url(download_url, APK_OUTPUT_DIR)


def download_with_playwright(package_name: str) -> Optional[str]:
    if sync_playwright is None:
        print("[WARN] Playwright is not installed. Skipping browser-based download.")
        return None

    print(f"[INFO] Downloading {package_name} from APKPure using Playwright fallback...")
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()

            search_url = f"https://apkpure.com/search?q={package_name}"
            page.goto(search_url, timeout=DEFAULT_TIMEOUT * 1000)
            page.wait_for_timeout(2000)

            result_links = page.locator("ul.search-res a.dd")
            count = result_links.count()
            for i in range(count):
                href = result_links.nth(i).get_attribute("href")
                if href and package_name in href:
                    result_links.nth(i).click()
                    break
            else:
                raise RuntimeError(f"Could not find matching app for package: {package_name}")

            page.wait_for_timeout(2000)
            page.click("a.download_apk_news")
            page.wait_for_timeout(2000)

            buttons = page.locator("a.jump-downloading-btn")
            for i in range(buttons.count()):
                dt_params = buttons.nth(i).get_attribute("dt-params")
                if not dt_params:
                    continue
                decoded_link = unquote(dt_params)
                if f"package_name={package_name}" not in decoded_link:
                    continue
                if "link_url=" not in decoded_link:
                    continue
                download_url = decoded_link.split("link_url=")[-1]
                with page.expect_download() as download_info:
                    page.goto(download_url)
                download = download_info.value

                os.makedirs(APK_OUTPUT_DIR, exist_ok=True)
                file_path = os.path.join(APK_OUTPUT_DIR, f"{package_name}.apk")
                download.save_as(file_path)
                print(f"[✓] APK downloaded to {file_path}")
                browser.close()
                return file_path

            browser.close()
            return None
    except Exception as exc:
        print(f"[!] Playwright download failed: {exc}")
        return None


def download_apk(package_name: str, use_playwright_fallback: bool = False) -> Optional[str]:
    cache = load_cache()
    if package_name in cache:
        print(f"[✓] Already downloaded: {package_name}")
        return cache[package_name]["path"]

    apk_path = download_from_apkpure(package_name)
    if apk_path:
        record_metadata(package_name, apk_path, "apkpure (http)")
        return apk_path

    if use_playwright_fallback:
        apk_path = download_with_playwright(package_name)
        if apk_path:
            record_metadata(package_name, apk_path, "apkpure (playwright)")
            return apk_path

    print("[✗] APK download failed.")
    return None


def re_find_all(pattern: str, text: str):
    return list(re.findall(pattern, text))
