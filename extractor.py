import zipfile
import os

def is_valid_main_apk(apk_path):
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            names = z.namelist()
            has_manifest = any("AndroidManifest.xml" in n for n in names)
            if has_manifest:
                print("  └─ ✅ Found AndroidManifest.xml")
            else:
                print("  └─ ❌ Missing AndroidManifest.xml")
            return has_manifest
    except zipfile.BadZipFile:
        print(f"[WARN] Not a valid ZIP (likely not a real APK): {apk_path}")
        return False
    except Exception as e:
        print(f"[ERROR] While checking APK structure: {e}")
        return False
def extract_apk_from_xapk(xapk_file_path, output_dir):
    try:
        os.makedirs(output_dir, exist_ok=True)

        print(f"[✓] Checking archive structure: {xapk_file_path}")
        with zipfile.ZipFile(xapk_file_path, 'r') as zip_ref:
            names = zip_ref.namelist()

            if "manifest.json" in names:
                print("[!] Detected wrapper APK (manifest.json present). Extracting contents...")
                zip_ref.extractall(output_dir)

                inner_apks = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".apk")]
                if not inner_apks:
                    print("[!] No APKs found inside wrapper!")
                    return []

                print("[✓] Found APK(s) inside wrapper")

                main_apks = [apk for apk in inner_apks if is_valid_main_apk(apk)]
                config_apks = [apk for apk in inner_apks if "config." in os.path.basename(apk)]

                return main_apks

            else:
                print("[✓] Looks like a regular APK/XAPK. Extracting normally...")
                zip_ref.extractall(output_dir)

                apk_files = []
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
