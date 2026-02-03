import os
import re
import stat
import unicodedata
import uuid
import zipfile
from typing import Iterable, Tuple

import magic

ZIP_MAGIC = b"PK\x03\x04"
ALLOWED_ZIP_MIME_TYPES = {
    "application/zip",
    "application/java-archive",
    "application/x-zip-compressed",
}

CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def normalize_unicode(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def is_safe_client_filename(filename: str) -> bool:
    if not filename:
        return False
    normalized = normalize_unicode(filename)
    if filename != normalized:
        return False
    if CONTROL_CHAR_RE.search(filename):
        return False
    if "/" in filename or "\\" in filename:
        return False
    if filename in {".", ".."}:
        return False
    if ".." in filename:
        return False
    return True


def generate_safe_filename(suffix: str) -> str:
    return f"{uuid.uuid4().hex}{suffix}"


def sniff_mime_type(path: str) -> str:
    return magic.from_file(path, mime=True)


def has_zip_signature(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            header = handle.read(4)
        return header == ZIP_MAGIC
    except OSError:
        return False


def validate_zip_mime(path: str) -> bool:
    return sniff_mime_type(path) in ALLOWED_ZIP_MIME_TYPES


def zip_entries(path: str) -> Iterable[str]:
    with zipfile.ZipFile(path, "r") as archive:
        return list(archive.namelist())


def validate_apk_structure(path: str) -> Tuple[bool, str]:
    if not has_zip_signature(path):
        return False, "missing zip signature"
    if not validate_zip_mime(path):
        return False, "unexpected mime type"
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            has_manifest = any(name.endswith("AndroidManifest.xml") for name in names)
            has_classes = any(name.endswith("classes.dex") for name in names)
            has_resources = any(name.endswith("resources.arsc") for name in names)
    except zipfile.BadZipFile:
        return False, "invalid zip"
    if not has_manifest:
        return False, "missing AndroidManifest.xml"
    if not (has_classes or has_resources):
        return False, "missing classes.dex or resources.arsc"
    return True, "ok"


def validate_xapk_structure(path: str) -> Tuple[bool, str]:
    if not has_zip_signature(path):
        return False, "missing zip signature"
    if not validate_zip_mime(path):
        return False, "unexpected mime type"
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
    except zipfile.BadZipFile:
        return False, "invalid zip"
    apk_entries = [name for name in names if name.endswith(".apk")]
    if not apk_entries:
        return False, "no apk entries"
    has_manifest = any(name.endswith("manifest.json") for name in names)
    if not has_manifest and len(apk_entries) < 2:
        return False, "missing xapk manifest"
    return True, "ok"


def is_zipinfo_symlink(info: zipfile.ZipInfo) -> bool:
    if info.create_system != 3:
        return False
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def safe_extract_zip(
    zip_path: str,
    dest_dir: str,
    max_bytes: int,
    max_files: int,
    per_file_max_bytes: int,
) -> None:
    os.makedirs(dest_dir, exist_ok=True)
    total_bytes = 0
    extracted = 0
    with zipfile.ZipFile(zip_path, "r") as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            extracted += 1
            if extracted > max_files:
                raise ValueError("archive contains too many files")
            if info.file_size > per_file_max_bytes:
                raise ValueError("archive entry too large")
            total_bytes += info.file_size
            if total_bytes > max_bytes:
                raise ValueError("archive exceeds size limit")
            if is_zipinfo_symlink(info):
                raise ValueError("archive contains symlink")
            normalized = normalize_unicode(info.filename)
            if normalized != info.filename:
                raise ValueError("archive contains non-normalized path")
            if os.path.isabs(info.filename):
                raise ValueError("archive contains absolute path")
            if ".." in info.filename.split("/"):
                raise ValueError("archive contains path traversal")
            target_path = os.path.realpath(os.path.join(dest_dir, info.filename))
            dest_root = os.path.realpath(dest_dir)
            if not target_path.startswith(dest_root + os.sep):
                raise ValueError("archive contains path traversal")
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with archive.open(info) as source, open(target_path, "wb") as target:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    target.write(chunk)


def safe_zip_directory(source_dir: str, output_zip: str) -> None:
    source_root = os.path.realpath(source_dir)
    output_zip_real = os.path.realpath(output_zip)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for root, dirs, files in os.walk(source_root):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for filename in files:
                full_path = os.path.join(root, filename)
                if os.path.islink(full_path):
                    continue
                if os.path.realpath(full_path) == output_zip_real:
                    continue
                rel_path = os.path.relpath(full_path, source_root)
                archive.write(full_path, rel_path)
