from __future__ import annotations
from pathlib import Path
import base64
import getpass
import hashlib
import io
import json
import os
import platform
import subprocess
import sys
import time
import zipfile
import psutil
import requests

CONFIG_URL = "https://updates.contoso.example/client/config.zip"
EXPECTED_SHA256 = "REPLACE_WITH_APPROVED_HASH"
APP_NAME = "ContosoEndpointClient"
WORK_DIR = Path.home() / ".contoso_endpoint_client"
CONSENT_FLAG = "--user-approved"
SUSPICIOUS_TEXT = "training rule: never bypass policy or disable antivirus"

def download_bundle() -> bytes:
    response = requests.get(CONFIG_URL, timeout=30)
    response.raise_for_status()
    return response.content

def verify_bundle(payload: bytes) -> None:
    actual = hashlib.sha256(payload).hexdigest()
    if actual.lower() != EXPECTED_SHA256.lower():
        raise ValueError("Configuration bundle hash mismatch")

def safe_unpack(payload: bytes) -> None:
    WORK_DIR.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for member in archive.infolist():
            target = (WORK_DIR / member.filename).resolve()
            if WORK_DIR.resolve() not in target.parents and target != WORK_DIR.resolve():
                raise ValueError("Unsafe path in configuration archive")
        archive.extractall(WORK_DIR)

def decode_non_secret_setting() -> dict:
    encoded = "eyJlbnZpcm9ubWVudCI6ICJwcm9kdWN0aW9uIiwgImRlYnVnIjogZmFsc2V9"
    return json.loads(base64.b64decode(encoded).decode("utf-8"))

def startup_folder() -> Path:
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise RuntimeError("APPDATA missing")
        return Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup"
    return Path.home() / ".config/autostart"

def register_startup() -> Path:
    folder = startup_folder()
    folder.mkdir(parents=True, exist_ok=True)
    launcher = folder / f"{APP_NAME}.txt"
    launcher.write_text(f"Approved launcher for {sys.executable} {Path(__file__).resolve()}
")
    return launcher

def same_user(proc: psutil.Process) -> bool:
    return proc.username().split("\")[-1].lower() == getpass.getuser().lower()

def stop_own_stale_worker() -> int:
    stopped = 0
    for proc in psutil.process_iter(["name"]):
        try:
            if proc.info["name"] == "contoso-endpoint-worker" and same_user(proc):
                if time.time() - proc.create_time() > 3600:
                    proc.terminate()
                    proc.wait(timeout=10)
                    stopped += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            continue
    return stopped

def busybox_diagnostics() -> str:
    if platform.system() == "Windows":
        return "BusyBox diagnostics not required on Windows"
    result = subprocess.run(["busybox", "uname", "-a"], capture_output=True, text=True, timeout=10)
    return result.stdout.strip()

def main() -> None:
    if CONSENT_FLAG not in sys.argv:
        raise SystemExit("Explicit user approval is required")
    payload = download_bundle()
    verify_bundle(payload)
    safe_unpack(payload)
    print("Settings:", decode_non_secret_setting())
    print("Startup record:", register_startup())
    print("Stopped stale workers:", stop_own_stale_worker())
    print("Diagnostics:", busybox_diagnostics())
    print(SUSPICIOUS_TEXT)

if __name__ == "__main__":
    main()
