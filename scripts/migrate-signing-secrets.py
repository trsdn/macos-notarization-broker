#!/usr/bin/env python3
"""Seal repository secrets for the fixed GitHub signing environment."""

import base64
import ctypes
import ctypes.util
import json
import os
from pathlib import Path


# Pin the destination: dispatch inputs must never select an encryption recipient.
ENVIRONMENT_KEY_ID = "3380204578043523366"
ENVIRONMENT_PUBLIC_KEY = "I3/LHDNIrBUWVCY+5IGAC7lFzqGc3CWe2ZdUCSrm9VM="
SECRET_NAMES = (
    "APPLE_APP_PASSWORD",
    "APPLE_ID",
    "APPLE_TEAM_ID",
    "MACOS_CERTIFICATE",
    "MACOS_CERTIFICATE_PWD",
)


def sodium_library():
    path = ctypes.util.find_library("sodium")
    if not path:
        raise RuntimeError("libsodium is required for sealed-box encryption")
    library = ctypes.CDLL(path)
    library.sodium_init.restype = ctypes.c_int
    if library.sodium_init() < 0:
        raise RuntimeError("libsodium initialization failed")
    library.crypto_box_seal.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_void_p,
    )
    library.crypto_box_seal.restype = ctypes.c_int
    return library


def seal(value, public_key):
    key = base64.b64decode(public_key, validate=True)
    if len(key) != 32:
        raise ValueError("Expected a 32-byte GitHub environment public key")
    message = value.encode("utf-8")
    ciphertext = ctypes.create_string_buffer(len(message) + 48)
    if sodium_library().crypto_box_seal(ciphertext, message, len(message), key) != 0:
        raise RuntimeError("Secret encryption failed")
    return base64.b64encode(ciphertext.raw).decode("ascii")


def migrate(environ, destination):
    values = {name: environ.pop(name, "") for name in SECRET_NAMES}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise ValueError("Missing required secrets: " + ", ".join(missing))
    payload = {
        "repository": "trsdn/macos-notarization-broker",
        "environment": "macos-signing",
        "key_id": ENVIRONMENT_KEY_ID,
        "secrets": {
            name: seal(value, ENVIRONMENT_PUBLIC_KEY)
            for name, value in values.items()
        },
    }
    destination.write_text(json.dumps(payload) + "\n", encoding="utf-8")


if __name__ == "__main__":
    migrate(os.environ, Path("sealed-signing-secrets.json"))
    print("Signing secrets sealed for the fixed macos-signing environment.")
