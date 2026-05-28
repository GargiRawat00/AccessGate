#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path

TRUST_STORE_PATH = Path("config/trust_store.json")
CURL_PATH = Path("/usr/bin/curl")


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def main() -> None:
    if not TRUST_STORE_PATH.exists():
        raise FileNotFoundError(f"Missing trust store: {TRUST_STORE_PATH}")

    if not CURL_PATH.exists():
        raise FileNotFoundError(f"Missing curl binary: {CURL_PATH}")

    data = json.loads(TRUST_STORE_PATH.read_text())
    curl_hash = sha256_file(CURL_PATH)

    updated = False

    for app in data.get("trusted_apps", []):
        if app.get("name") == "curl" and app.get("path") == str(CURL_PATH):
            app["sha256"] = curl_hash
            updated = True
            break

    if not updated:
        data.setdefault("trusted_apps", []).append(
            {
                "name": "curl",
                "path": str(CURL_PATH),
                "sha256": curl_hash,
            }
        )

    TRUST_STORE_PATH.write_text(json.dumps(data, indent=2) + "\n")

    print(f"Enrolled curl trust hash: {curl_hash}")


if __name__ == "__main__":
    main()
