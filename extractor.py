import os
import zipfile
from typing import List

from apkspider.security import (
    safe_extract_zip,
    validate_apk_structure,
    validate_xapk_structure,
)

DEFAULT_MAX_EXTRACT_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_EXTRACT_FILES = 10000
DEFAULT_MAX_FILE_BYTES = 200 * 1024 * 1024


def is_valid_main_apk(apk_path: str) -> bool:
    valid, _ = validate_apk_structure(apk_path)
    if valid:
        print("  └─ ✅ Found AndroidManifest.xml")
    else:
        print("  └─ ❌ Missing AndroidManifest.xml")
    return valid


def extract_apk_from_xapk(
    xapk_file_path: str,
    output_dir: str,
    max_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
    max_files: int = DEFAULT_MAX_EXTRACT_FILES,
    per_file_max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> List[str]:
    try:
        os.makedirs(output_dir, exist_ok=True)

        print(f"[✓] Checking archive structure: {xapk_file_path}")
        is_xapk, _ = validate_xapk_structure(xapk_file_path)
        if not is_xapk:
            print("[!] Archive did not pass XAPK validation; treating as APK.")
            return []

        with zipfile.ZipFile(xapk_file_path, "r") as zip_ref:
            names = zip_ref.namelist()

        if "manifest.json" in names:
            print("[!] Detected wrapper APK (manifest.json present). Extracting contents...")
            safe_extract_zip(
                xapk_file_path,
                output_dir,
                max_bytes=max_bytes,
                max_files=max_files,
                per_file_max_bytes=per_file_max_bytes,
            )

            inner_apks = [
                os.path.join(output_dir, f)
                for f in os.listdir(output_dir)
                if f.endswith(".apk")
            ]
            if not inner_apks:
                print("[!] No APKs found inside wrapper!")
                return []

            print("[✓] Found APK(s) inside wrapper")

            main_apks = [apk for apk in inner_apks if is_valid_main_apk(apk)]
            return main_apks

        print("[✓] Looks like a regular APK/XAPK. Extracting normally...")
        safe_extract_zip(
            xapk_file_path,
            output_dir,
            max_bytes=max_bytes,
            max_files=max_files,
            per_file_max_bytes=per_file_max_bytes,
        )

        apk_files: List[str] = []
        for root, _, files in os.walk(output_dir):
            for file in files:
                if file.endswith(".apk"):
                    apk_files.append(os.path.join(root, file))

        main_apks = [apk for apk in apk_files if is_valid_main_apk(apk)]
        config_apks = [apk for apk in apk_files if "config." in os.path.basename(apk)]

        return main_apks + config_apks

    except zipfile.BadZipFile:
        print("[!] Not a valid ZIP archive.")
        return []
    except Exception as e:
        print(f"[!] Error during extraction: {e}")
        return []
