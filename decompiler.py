import os
import shutil
import subprocess

def find_apktool():
    """Finds APKTool, ensuring it is installed and in PATH."""
    apktool_path = shutil.which("apktool")
    if apktool_path:
        return apktool_path
    raise FileNotFoundError("[!] APKTool is not installed or not in PATH. Please install it before running this script.")

def is_valid_apk(apk_path):
    """Checks if the file is a valid APK (basic check)."""
    try:
        with open(apk_path, "rb") as f:
            header = f.read(4)
            return header == b'PK\x03\x04'
    except Exception:
        return False

def decompile_apk(apk_file_path, output_dir):
    """Decompiles an APK using apktool with extra validation and verbose logging."""
    if not os.path.isfile(apk_file_path):
        print(f"[!] File not found: {apk_file_path}")
        return None

    if not is_valid_apk(apk_file_path):
        print(f"[!] Invalid APK (not a zip): {apk_file_path}")
        return None

    try:
        apktool_command = find_apktool()

        if os.path.exists(output_dir):
            print(f"[~] Cleaning existing output directory: {output_dir}")
            shutil.rmtree(output_dir)

        print(f"[✓] Decompiling APK: {apk_file_path}")
        cmd = [apktool_command, "d", apk_file_path, "-o", output_dir, "-f"]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[!] APKTool failed with exit code {result.returncode}")
            return None

        print(f"[✓] Decompiled APK to: {output_dir}")
        return output_dir

    except FileNotFoundError as fnf_error:
        print(f"[!] Error: {fnf_error}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None
