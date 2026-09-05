#!/usr/bin/env python3
"""Install only checksum-pinned upstream age executables into private local state."""
from __future__ import annotations

import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

VERSION = "v1.3.2"
ARCHIVES = {
    ("Darwin", "arm64"): ("darwin-arm64", "e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5"),
    ("Darwin", "x86_64"): ("darwin-amd64", "1d1e4bc66e1427edad7739ae7616157de0e79db8b6d2a1497d7d9925fb06a539"),
    ("Linux", "x86_64"): ("linux-amd64", "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"),
    ("Linux", "aarch64"): ("linux-arm64", "6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4"),
}
MAX_DOWNLOAD = 32 * 1024 * 1024


def unpack_verified(data: bytes, expected_sha: str, destination: Path) -> None:
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError("age distribution checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for name in ("age", "age-keygen"):
            members = [m for m in archive.getmembers() if m.name == f"age/{name}"]
            if len(members) != 1 or not members[0].isfile() or members[0].size > MAX_DOWNLOAD:
                raise ValueError("Unsafe age distribution")
            source = archive.extractfile(members[0])
            if source is None:
                raise ValueError("Missing age executable")
            path = destination / name
            if path.is_symlink():
                raise ValueError("Unsafe age destination")
            path.write_bytes(source.read())
            path.chmod(0o700)


def install(destination: Path) -> Path:
    target, checksum = ARCHIVES[(platform.system(), platform.machine())]
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.is_symlink():
        raise ValueError("Unsafe age directory")
    archive_path = destination / f"age-{VERSION}-{target}.tar.gz"
    if archive_path.is_symlink():
        raise ValueError("Unsafe age cache")
    if archive_path.exists():
        data = archive_path.read_bytes()
    else:
        url = f"https://github.com/FiloSottile/age/releases/download/{VERSION}/{archive_path.name}"
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(MAX_DOWNLOAD + 1)
        if len(data) > MAX_DOWNLOAD or hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError("age distribution verification failed")
        archive_path.write_bytes(data)
        archive_path.chmod(0o600)
    # Re-extract from the verified archive instead of trusting cached executables.
    unpack_verified(data, checksum, destination)
    return destination / "age"
