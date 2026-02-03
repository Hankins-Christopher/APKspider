import os
import shutil
from typing import Optional

from apkspider.analysis import run_analysis
from apkspider.decompiler import decompile_apk
from apkspider.extractor import (
    DEFAULT_MAX_EXTRACT_BYTES,
    DEFAULT_MAX_EXTRACT_FILES,
    DEFAULT_MAX_FILE_BYTES,
    extract_apk_from_xapk,
)


def select_main_apk(apks, package_name: str) -> Optional[str]:
    if not apks:
        return None
    for apk in apks:
        if package_name and package_name in os.path.basename(apk):
            return apk
    return apks[0]


def analyze_uploaded_apk(
    file_path: str,
    output_dir: str,
    package_name: str,
    extract_limits: Optional[dict] = None,
    decompile_timeout: Optional[int] = None,
) -> Optional[str]:
    extract_limits = extract_limits or {}
    extract_dir = os.path.join(output_dir, "extracted")
    os.makedirs(output_dir, exist_ok=True)

    extracted_apks = extract_apk_from_xapk(
        file_path,
        extract_dir,
        max_bytes=extract_limits.get("max_bytes", DEFAULT_MAX_EXTRACT_BYTES),
        max_files=extract_limits.get("max_files", DEFAULT_MAX_EXTRACT_FILES),
        per_file_max_bytes=extract_limits.get("per_file_max_bytes", DEFAULT_MAX_FILE_BYTES),
    )
    if not extracted_apks:
        extracted_apks = [file_path]

    main_apk = select_main_apk(extracted_apks, package_name)
    if not main_apk:
        return None

    real_main = os.path.realpath(main_apk)
    real_output = os.path.realpath(output_dir)
    real_input = os.path.realpath(file_path)
    if not (real_main.startswith(real_output + os.sep) or real_main == real_input):
        return None

    decompiled_main = decompile_apk(
        main_apk,
        os.path.join(output_dir, "main_apk_decompiled"),
        timeout_seconds=decompile_timeout,
    )
    if not decompiled_main:
        return None

    report_dir = os.path.join(output_dir, "analysis_report")
    run_analysis(decompiled_main, report_dir, target=package_name or os.path.basename(main_apk))

    shutil.rmtree(extract_dir, ignore_errors=True)
    return report_dir
