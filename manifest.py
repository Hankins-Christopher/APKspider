import os
import xml.etree.ElementTree as ET
from typing import Dict, List

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _get_attrib(element: ET.Element, name: str) -> str:
    return element.attrib.get(f"{{{ANDROID_NS}}}{name}", "")


def parse_manifest(decompiled_dir: str) -> Dict[str, List[str] | str]:
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return {
            "package_name": "",
            "version_name": "",
            "version_code": "",
            "min_sdk": "",
            "target_sdk": "",
            "permissions": [],
        }

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        return {
            "package_name": "",
            "version_name": "",
            "version_code": "",
            "min_sdk": "",
            "target_sdk": "",
            "permissions": [],
        }

    package_name = root.attrib.get("package", "")
    version_name = _get_attrib(root, "versionName")
    version_code = _get_attrib(root, "versionCode")

    min_sdk = ""
    target_sdk = ""
    permissions: List[str] = []

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk = _get_attrib(uses_sdk, "minSdkVersion")
        target_sdk = _get_attrib(uses_sdk, "targetSdkVersion")

    for perm in root.findall("uses-permission"):
        name = _get_attrib(perm, "name")
        if name:
            permissions.append(name)

    return {
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": permissions,
    }
