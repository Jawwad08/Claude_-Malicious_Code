import hashlib
from pathlib import Path
import requests

URL = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
EXPECTED_SHA256 = "REPLACE_WITH_PUBLISHED_SHA256"
OUTPUT = Path("python-installer.exe")

def download(url: str) -> bytes:
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    return response.content

def verify(data: bytes, expected: str) -> None:
    actual = hashlib.sha256(data).hexdigest()
    if actual.lower() != expected.lower():
        raise SystemExit("Hash mismatch - file will not be saved")

def main() -> None:
    payload = download(URL)
    verify(payload, EXPECTED_SHA256)
    OUTPUT.write_bytes(payload)
    print(f"Verified installer saved to {OUTPUT}")

if __name__ == "__main__":
    main()
