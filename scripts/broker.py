#!/usr/bin/env python3
"""Broker-owned build, validation, signing, and notarization operations."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import plistlib
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
PROFILE_ROOT = ROOT / "profiles"
PROFILE_FILE = PROFILE_ROOT / "apps.json"
TAG_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
REQUEST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
FULL_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
NESTED_BUNDLE_SUFFIXES = (".app", ".appex", ".bundle", ".framework", ".xpc")


class BrokerError(RuntimeError):
    """A user-facing broker policy or operation failure."""


def fail(message: str) -> None:
    raise BrokerError(message)


def load_profiles() -> dict[str, Any]:
    with PROFILE_FILE.open("r", encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("schema_version") != 1:
        fail("Unsupported profile schema version.")
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        fail("Profile configuration is empty.")

    required = {
        "repository",
        "repository_id",
        "build_adapter",
        "bundle_name",
        "bundle_identifier",
        "bundle_display_name",
        "executable",
        "package_type",
        "architectures",
        "minimum_system_version",
        "entitlements",
        "max_archive_bytes",
        "max_uncompressed_bytes",
        "max_files",
        "artifacts",
    }
    allowed_adapters = {
        "md2loop-xcode",
        "openwritr-swiftpm",
        "ptionsplus-xcode",
        "teleprompter-swiftpm",
    }
    for name, profile in profiles.items():
        if not re.fullmatch(r"[a-z0-9-]+", name):
            fail(f"Invalid profile name: {name}")
        missing = required - set(profile)
        if missing:
            fail(f"Profile {name} is missing fields: {', '.join(sorted(missing))}")
        if profile["build_adapter"] not in allowed_adapters:
            fail(f"Profile {name} has an unsupported build adapter.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", profile["repository"]):
            fail(f"Profile {name} has an invalid repository.")
        if not isinstance(profile["repository_id"], int) or profile["repository_id"] <= 0:
            fail(f"Profile {name} has an invalid repository ID.")
        if profile["package_type"] != "APPL":
            fail(f"Profile {name} must describe an application bundle.")
        if profile["architectures"] != ["arm64"]:
            fail(f"Profile {name} must currently require exactly arm64.")
        entitlement_path = safe_profile_path(profile["entitlements"])
        with entitlement_path.open("rb") as handle:
            entitlements = plistlib.load(handle)
        if not isinstance(entitlements, dict):
            fail(f"Profile {name} entitlements must be a plist dictionary.")
        if "dependency_lock" in profile:
            safe_profile_path(profile["dependency_lock"])
        for artifact in profile["artifacts"]:
            if artifact.get("type") not in {"zip", "dmg"}:
                fail(f"Profile {name} has an unsupported artifact type.")
            rendered = artifact.get("name", "").replace("{version}", "1.2.3")
            if not rendered or Path(rendered).name != rendered:
                fail(f"Profile {name} has an unsafe artifact name.")
    return profiles


def get_profile(app: str) -> dict[str, Any]:
    profiles = load_profiles()
    if app not in profiles:
        fail(f"Unknown application profile: {app}")
    return profiles[app]


def safe_profile_path(relative_path: str) -> Path:
    candidate = (PROFILE_ROOT / relative_path).resolve()
    try:
        candidate.relative_to(PROFILE_ROOT.resolve())
    except ValueError:
        fail(f"Profile path escapes the profile directory: {relative_path}")
    if not candidate.is_file():
        fail(f"Profile file does not exist: {relative_path}")
    return candidate


def validate_tag(tag: str) -> str:
    if not TAG_PATTERN.fullmatch(tag):
        fail("Tag must be an exact version tag such as v1.0.2.")
    return tag[1:]


def normalize_request_id(request_id: str) -> str:
    if not request_id:
        run_id = os.environ.get("GITHUB_RUN_ID", "local")
        request_id = f"manual-{run_id}"
    if not REQUEST_PATTERN.fullmatch(request_id):
        fail("Request ID must be 1-80 safe alphanumeric, dot, underscore, or dash characters.")
    return request_id


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(path)


def append_github_outputs(values: dict[str, Any]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            text = "" if value is None else str(value)
            if "\n" in text or "\r" in text:
                fail(f"GitHub output {key} contains a newline.")
            handle.write(f"{key}={text}\n")


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
    check: bool = True,
    display: bool = True,
) -> subprocess.CompletedProcess[str]:
    if display:
        print("+", " ".join(shlex.quote(part) for part in command), flush=True)
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if check and completed.returncode != 0:
        details = ""
        if capture:
            details = (completed.stderr or completed.stdout or "").strip()
        suffix = f": {details}" if details else ""
        fail(f"Command failed ({completed.returncode}): {command[0]}{suffix}")
    return completed


def require_tools(names: Iterable[str]) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        fail(f"Required tools are missing: {', '.join(missing)}")


def github_api(path: str) -> dict[str, Any]:
    url = f"https://api.github.com{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "macos-notarization-broker",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        fail(f"GitHub API request failed ({error.code}) for {path}: {body[:500]}")
    except urllib.error.URLError as error:
        fail(f"GitHub API request failed for {path}: {error}")


def profile_digest(app: str, profile: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    paths = [PROFILE_FILE, safe_profile_path(profile["entitlements"])]
    if "dependency_lock" in profile:
        paths.append(safe_profile_path(profile["dependency_lock"]))
    digest.update(app.encode("utf-8") + b"\0")
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def command_resolve(args: argparse.Namespace) -> None:
    version = validate_tag(args.tag)
    request_id = normalize_request_id(args.request_id)
    profile = get_profile(args.app)
    repository = profile["repository"]
    repository_document = github_api(f"/repos/{repository}")
    if repository_document.get("id") != profile["repository_id"]:
        fail("Repository numeric identity does not match the broker profile.")
    if repository_document.get("full_name", "").lower() != repository.lower():
        fail("Repository full name does not match the broker profile.")

    encoded_tag = urllib.parse.quote(args.tag, safe="")
    reference = github_api(f"/repos/{repository}/git/ref/tags/{encoded_tag}")
    target = reference.get("object") or {}
    object_type = target.get("type")
    object_sha = target.get("sha", "")
    if not FULL_SHA_PATTERN.fullmatch(object_sha):
        fail("The tag reference did not resolve to a full SHA.")
    ref_target_sha = object_sha
    tag_object_sha = ""
    seen: set[str] = set()
    for _ in range(8):
        if object_type == "commit":
            break
        if object_type != "tag":
            fail(f"Tag resolves to unsupported Git object type: {object_type}")
        if object_sha in seen:
            fail("Annotated tag dereference cycle detected.")
        seen.add(object_sha)
        if not tag_object_sha:
            tag_object_sha = object_sha
        tag_document = github_api(f"/repos/{repository}/git/tags/{object_sha}")
        target = tag_document.get("object") or {}
        object_type = target.get("type")
        object_sha = target.get("sha", "")
        if not FULL_SHA_PATTERN.fullmatch(object_sha):
            fail("Annotated tag did not resolve to a full SHA.")
    else:
        fail("Annotated tag dereference depth exceeded.")
    if object_type != "commit":
        fail("Tag did not resolve to a commit.")

    commit_document = github_api(f"/repos/{repository}/git/commits/{object_sha}")
    commit_sha = commit_document.get("sha", "")
    if not FULL_SHA_PATTERN.fullmatch(commit_sha):
        fail("Resolved commit SHA is invalid.")
    if args.expect_sha and commit_sha != args.expect_sha:
        fail(f"Tag moved: expected {args.expect_sha}, currently resolves to {commit_sha}.")

    manifest = {
        "schema_version": 1,
        "profile": args.app,
        "profile_digest": profile_digest(args.app, profile),
        "request_id": request_id,
        "source": {
            "repository": repository,
            "repository_id": profile["repository_id"],
            "tag": args.tag,
            "ref_target_sha": ref_target_sha,
            "tag_object_sha": tag_object_sha or None,
            "commit_sha": commit_sha,
        },
        "version": version,
    }
    if args.output:
        write_json(Path(args.output), manifest)

    outputs = {
        "app": args.app,
        "tag": args.tag,
        "repository": repository,
        "repository_id": profile["repository_id"],
        "ref_target_sha": ref_target_sha,
        "tag_object_sha": tag_object_sha,
        "commit_sha": commit_sha,
        "version": version,
        "request_id": request_id,
        "profile_digest": manifest["profile_digest"],
        "artifact_name": f"{args.app}-{version}-{request_id}",
    }
    append_github_outputs(outputs)
    print(json.dumps(manifest, indent=2, sort_keys=True))


def ensure_source_file(source: Path, relative_path: str) -> Path:
    path = source / relative_path
    if path.is_symlink() or not path.is_file():
        fail(f"Required source file is missing or unsafe: {relative_path}")
    return path


def copy_app(source_app: Path, destination_app: Path) -> None:
    if not source_app.is_dir() or source_app.is_symlink():
        fail(f"Built app bundle was not found: {source_app}")
    destination_app.parent.mkdir(parents=True, exist_ok=True)
    if destination_app.exists():
        shutil.rmtree(destination_app)
    run(["ditto", str(source_app), str(destination_app)])


def build_md2loop(source: Path, work: Path, profile: dict[str, Any], version: str, build_number: str) -> Path:
    ensure_source_file(source, "md2loop.xcodeproj/project.pbxproj")
    lock = safe_profile_path(profile["dependency_lock"])
    workspace_lock = (
        source
        / "md2loop.xcodeproj"
        / "project.xcworkspace"
        / "xcshareddata"
        / "swiftpm"
        / "Package.resolved"
    )
    workspace_lock.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(lock, workspace_lock)
    derived_data = work / "DerivedData"
    packages = work / "SourcePackages"
    common = [
        "xcodebuild",
        "-project",
        "md2loop.xcodeproj",
        "-scheme",
        "md2loop",
        "-clonedSourcePackagesDirPath",
        str(packages),
        "-onlyUsePackageVersionsFromResolvedFile",
    ]
    run(common + ["-resolvePackageDependencies"], cwd=source)
    run(
        common
        + [
            "-configuration",
            "Release",
            "-derivedDataPath",
            str(derived_data),
            "clean",
            "build",
            f"MARKETING_VERSION={version}",
            f"CURRENT_PROJECT_VERSION={build_number}",
            "ENABLE_HARDENED_RUNTIME=YES",
            "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO",
            "CODE_SIGNING_ALLOWED=NO",
            "CODE_SIGNING_REQUIRED=NO",
            "ARCHS=arm64",
            "ONLY_ACTIVE_ARCH=NO",
        ],
        cwd=source,
    )
    return derived_data / "Build" / "Products" / "Release" / profile["bundle_name"]


def swift_build(source: Path, product: str, require_lock: bool) -> Path:
    command = [
        "swift",
        "build",
        "--package-path",
        str(source),
        "--configuration",
        "release",
    ]
    if require_lock:
        ensure_source_file(source, "Package.resolved")
        command.append("--only-use-versions-from-resolved-file")
    run(command + ["--product", product])
    result = run(command + ["--show-bin-path"], capture=True)
    bin_path = Path(result.stdout.strip())
    executable = bin_path / product
    if not executable.is_file():
        fail(f"SwiftPM did not produce the expected executable: {executable}")
    return executable


def assemble_openwritr(source: Path, work: Path, profile: dict[str, Any]) -> Path:
    executable = swift_build(source, "OpenWritr", require_lock=True)
    app = work / profile["bundle_name"]
    macos = app / "Contents" / "MacOS"
    resources = app / "Contents" / "Resources"
    macos.mkdir(parents=True)
    resources.mkdir(parents=True)
    shutil.copy2(executable, macos / profile["executable"])
    shutil.copy2(ensure_source_file(source, "Resources/AppIcon.icns"), resources / "AppIcon.icns")
    shutil.copy2(
        ensure_source_file(source, "Sources/OpenWritr/Resources/cleanup-prompt-profiles.json"),
        resources / "cleanup-prompt-profiles.json",
    )
    info_path = app / "Contents" / "Info.plist"
    shutil.copy2(ensure_source_file(source, "Info.plist"), info_path)
    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    info.update(
        {
            "CFBundleExecutable": profile["executable"],
            "CFBundleIconFile": "AppIcon",
            "CFBundlePackageType": "APPL",
            "CFBundleDisplayName": profile["bundle_display_name"],
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": profile["minimum_system_version"],
        }
    )
    with info_path.open("wb") as handle:
        plistlib.dump(info, handle, sort_keys=True)
    return app


def build_ptionsplus(
    source: Path, work: Path, profile: dict[str, Any], version: str, build_number: str
) -> Path:
    ensure_source_file(source, "PtionsPlus.xcodeproj/project.pbxproj")
    derived_data = work / "DerivedData"
    run(
        [
            "xcodebuild",
            "-project",
            "PtionsPlus.xcodeproj",
            "-scheme",
            "Ptions+",
            "-configuration",
            "Release",
            "-derivedDataPath",
            str(derived_data),
            "clean",
            "build",
            f"MARKETING_VERSION={version}",
            f"CURRENT_PROJECT_VERSION={build_number}",
            "ENABLE_HARDENED_RUNTIME=YES",
            "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO",
            "CODE_SIGNING_ALLOWED=NO",
            "CODE_SIGNING_REQUIRED=NO",
            "ARCHS=arm64",
            "ONLY_ACTIVE_ARCH=NO",
        ],
        cwd=source,
    )
    return derived_data / "Build" / "Products" / "Release" / profile["bundle_name"]


def assemble_teleprompter(source: Path, work: Path, profile: dict[str, Any]) -> Path:
    executable = swift_build(source, "TeleprompterMirror", require_lock=False)
    app = work / profile["bundle_name"]
    macos = app / "Contents" / "MacOS"
    resources = app / "Contents" / "Resources"
    macos.mkdir(parents=True)
    resources.mkdir(parents=True)
    shutil.copy2(executable, macos / profile["executable"])
    shutil.copy2(ensure_source_file(source, "Config/Info.plist"), app / "Contents" / "Info.plist")
    return app


def command_build(args: argparse.Namespace) -> None:
    require_tools(["ditto", "file", "git", "lipo", "swift", "xcodebuild"])
    version = validate_tag(f"v{args.version}")
    profile = get_profile(args.app)
    source = Path(args.source).resolve()
    if not source.is_dir():
        fail("Source directory does not exist.")
    if not FULL_SHA_PATTERN.fullmatch(args.commit_sha):
        fail("Build requires a full source commit SHA.")
    actual_sha = run(["git", "rev-parse", "HEAD"], cwd=source, capture=True).stdout.strip()
    if actual_sha != args.commit_sha:
        fail(f"Source checkout mismatch: expected {args.commit_sha}, got {actual_sha}.")
    status = run(["git", "status", "--porcelain"], cwd=source, capture=True).stdout.strip()
    if status:
        fail("Source checkout must be clean before the broker-owned build starts.")

    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="broker-build-") as temporary:
        work = Path(temporary)
        adapter = profile["build_adapter"]
        if adapter == "md2loop-xcode":
            built_app = build_md2loop(source, work, profile, version, args.build_number)
        elif adapter == "openwritr-swiftpm":
            built_app = assemble_openwritr(source, work, profile)
        elif adapter == "ptionsplus-xcode":
            built_app = build_ptionsplus(source, work, profile, version, args.build_number)
        elif adapter == "teleprompter-swiftpm":
            built_app = assemble_teleprompter(source, work, profile)
        else:
            fail(f"Unsupported build adapter: {adapter}")

        staged_app = work / "unsigned" / profile["bundle_name"]
        copy_app(built_app, staged_app)
        if output.exists():
            output.unlink()
        run(["ditto", "-c", "-k", "--norsrc", "--keepParent", str(staged_app), str(output)])
    print(f"Unsigned application archive: {output}")
    print(f"SHA-256: {sha256_file(output)}")


def normalized_zip_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        fail("Archive contains an invalid path.")
    path = PurePosixPath(name)
    if path.is_absolute():
        fail(f"Archive contains an absolute path: {name}")
    if any(part in {"", ".", ".."} for part in path.parts):
        fail(f"Archive contains an unsafe path: {name}")
    if any(any(ord(character) < 32 for character in part) for part in path.parts):
        fail(f"Archive contains a control character in a path: {name}")
    return path


def inspect_zip(archive: Path, profile: dict[str, Any]) -> dict[str, Any]:
    if archive.stat().st_size > profile["max_archive_bytes"]:
        fail("Unsigned archive exceeds the profile size limit.")
    expected_root = profile["bundle_name"]
    seen: set[str] = set()
    total_size = 0
    file_count = 0
    with zipfile.ZipFile(archive) as handle:
        for entry in handle.infolist():
            path = normalized_zip_path(entry.filename)
            if "__MACOSX" in path.parts or any(part.startswith("._") for part in path.parts):
                fail(f"Archive contains AppleDouble metadata: {entry.filename}")
            normalized = path.as_posix().rstrip("/")
            if normalized in seen:
                fail(f"Archive contains a duplicate path: {normalized}")
            seen.add(normalized)
            if path.parts[0] != expected_root:
                fail(f"Archive contains content outside {expected_root}: {entry.filename}")
            if entry.flag_bits & 0x1:
                fail("Encrypted ZIP entries are not allowed.")
            mode = entry.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                fail(f"Archive contains a symlink or special file: {entry.filename}")
            total_size += entry.file_size
            if not entry.is_dir():
                file_count += 1
            if total_size > profile["max_uncompressed_bytes"]:
                fail("Unsigned archive exceeds the uncompressed size limit.")
            if file_count > profile["max_files"]:
                fail("Unsigned archive exceeds the file-count limit.")
    if expected_root not in seen:
        fail(f"Archive does not contain the expected root bundle: {expected_root}")
    return {
        "compressed_bytes": archive.stat().st_size,
        "uncompressed_bytes": total_size,
        "file_count": file_count,
    }


def is_macho(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size < 4:
        return False
    with path.open("rb") as handle:
        return handle.read(4) in MACHO_MAGICS


def read_bundle_info(app_path: Path) -> dict[str, Any]:
    info_path = app_path / "Contents" / "Info.plist"
    if info_path.is_symlink() or not info_path.is_file():
        fail("Application is missing a regular Contents/Info.plist.")
    try:
        with info_path.open("rb") as handle:
            info = plistlib.load(handle)
    except Exception as error:
        fail(f"Application Info.plist is invalid: {error}")
    if not isinstance(info, dict):
        fail("Application Info.plist must be a dictionary.")
    return info


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
            content_hash = ""
        elif stat.S_ISREG(metadata.st_mode):
            kind = "file"
            content_hash = sha256_file(path)
        else:
            fail(f"Tree contains a symlink or special file: {relative}")
        digest.update(
            f"{kind}\0{relative}\0{stat.S_IMODE(metadata.st_mode):04o}\0"
            f"{metadata.st_size}\0{content_hash}\n".encode("utf-8")
        )
    return digest.hexdigest()


def validate_app_tree(
    app_path: Path,
    profile: dict[str, Any],
    version: str,
    *,
    require_unsigned: bool,
) -> dict[str, Any]:
    if app_path.is_symlink() or not app_path.is_dir():
        fail("Expected application bundle root was not found.")
    contents = app_path / "Contents"
    macos = contents / "MacOS"
    resources = contents / "Resources"
    for required in (contents, macos, resources):
        if required.is_symlink() or not required.is_dir():
            fail(f"Application bundle is missing required directory: {required.relative_to(app_path)}")

    file_count = 0
    total_size = 0
    main_executable = macos / profile["executable"]
    for path in app_path.rglob("*"):
        relative = path.relative_to(app_path)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            fail(f"Application contains a symlink or special file: {relative}")
        if path.is_dir() and path != app_path:
            if path.name.endswith(NESTED_BUNDLE_SUFFIXES):
                fail(f"Nested bundles are not allowed for this profile: {relative}")
            continue
        file_count += 1
        total_size += metadata.st_size
        if file_count > profile["max_files"]:
            fail("Application exceeds the file-count limit.")
        if total_size > profile["max_uncompressed_bytes"]:
            fail("Application exceeds the size limit.")
        if path != main_executable and is_macho(path):
            fail(f"Unexpected nested Mach-O code: {relative}")
        if path != main_executable and metadata.st_mode & 0o111:
            fail(f"Unexpected executable file: {relative}")
        if path.name == "embedded.provisionprofile" or "_CodeSignature" in relative.parts:
            fail(f"Unsigned input contains signing material: {relative}")

    if main_executable.is_symlink() or not main_executable.is_file():
        fail("Application main executable is missing or unsafe.")
    if not main_executable.stat().st_mode & 0o111:
        fail("Application main executable is not executable.")
    file_result = run(["file", "-b", str(main_executable)], capture=True)
    if "Mach-O" not in file_result.stdout:
        fail("Application main executable is not Mach-O.")
    architectures = run(["lipo", "-archs", str(main_executable)], capture=True).stdout.split()
    if sorted(architectures) != sorted(profile["architectures"]):
        fail(
            "Application architectures do not match profile: "
            f"expected {profile['architectures']}, got {architectures}"
        )

    info = read_bundle_info(app_path)
    checks = {
        "CFBundleIdentifier": profile["bundle_identifier"],
        "CFBundleExecutable": profile["executable"],
        "CFBundlePackageType": profile["package_type"],
        "CFBundleShortVersionString": version,
        "LSMinimumSystemVersion": profile["minimum_system_version"],
    }
    for key, expected in checks.items():
        if str(info.get(key, "")) != expected:
            fail(f"{key} mismatch: expected {expected!r}, got {info.get(key)!r}")
    display_name = info.get("CFBundleDisplayName") or info.get("CFBundleName")
    if display_name != profile["bundle_display_name"]:
        fail(
            "Bundle display name mismatch: "
            f"expected {profile['bundle_display_name']!r}, got {display_name!r}"
        )
    bundle_version = str(info.get("CFBundleVersion", ""))
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", bundle_version):
        fail("CFBundleVersion must be a non-empty numeric dotted version.")

    if require_unsigned:
        signature = run(
            ["codesign", "-dv", "--verbose=4", str(app_path)],
            capture=True,
            check=False,
        )
        if signature.returncode == 0:
            signature_details = (signature.stdout or "") + (signature.stderr or "")
            allowed_linker_signature = (
                "Signature=adhoc" in signature_details
                and "linker-signed" in signature_details
                and "TeamIdentifier=not set" in signature_details
                and "Authority=" not in signature_details
                and not read_signed_entitlements(app_path)
            )
            if not allowed_linker_signature:
                fail(
                    "Input application has a non-linker or identity-backed signature; "
                    "the broker accepts only unsigned or linker-signed bundles."
                )

    return {
        "bundle_name": profile["bundle_name"],
        "bundle_identifier": profile["bundle_identifier"],
        "bundle_version": bundle_version,
        "executable": profile["executable"],
        "architectures": architectures,
        "file_count": file_count,
        "uncompressed_bytes": total_size,
        "tree_sha256": tree_digest(app_path),
        "main_executable_sha256": sha256_file(main_executable),
    }


def extract_and_validate(
    archive: Path,
    extract_to: Path,
    profile: dict[str, Any],
    version: str,
    *,
    require_unsigned: bool,
) -> tuple[Path, dict[str, Any]]:
    archive_info = inspect_zip(archive, profile)
    if extract_to.exists():
        shutil.rmtree(extract_to)
    extract_to.mkdir(parents=True)
    run(["ditto", "-x", "-k", str(archive), str(extract_to)])
    app_path = extract_to / profile["bundle_name"]
    app_info = validate_app_tree(app_path, profile, version, require_unsigned=require_unsigned)
    return app_path, {
        "archive": {
            "sha256": sha256_file(archive),
            **archive_info,
        },
        "application": app_info,
    }


def command_validate(args: argparse.Namespace) -> None:
    require_tools(["codesign", "ditto", "file", "lipo", "xattr"])
    version = validate_tag(f"v{args.version}")
    profile = get_profile(args.app)
    archive = Path(args.archive).resolve()
    if not archive.is_file():
        fail("Unsigned application archive does not exist.")
    archive_sha = sha256_file(archive)
    if args.expected_archive_sha and archive_sha != args.expected_archive_sha:
        fail(
            f"Archive digest mismatch: expected {args.expected_archive_sha}, got {archive_sha}."
        )

    extract_to = Path(args.extract_to).resolve()
    app_path, result = extract_and_validate(
        archive, extract_to, profile, version, require_unsigned=True
    )
    if args.expected_tree_sha and result["application"]["tree_sha256"] != args.expected_tree_sha:
        fail("Application tree digest does not match the preflight result.")

    validated_sha = archive_sha
    validated_archive = None
    if args.validated_archive:
        validated_archive = Path(args.validated_archive).resolve()
        validated_archive.parent.mkdir(parents=True, exist_ok=True)
        if validated_archive.exists():
            validated_archive.unlink()
        run(["xattr", "-cr", str(app_path)])
        run(
            [
                "ditto",
                "-c",
                "-k",
                "--norsrc",
                "--keepParent",
                str(app_path),
                str(validated_archive),
            ]
        )
        validated_sha = sha256_file(validated_archive)
        result["validated_archive"] = {
            "sha256": validated_sha,
            "bytes": validated_archive.stat().st_size,
        }

    result.update(
        {
            "schema_version": 1,
            "profile": args.app,
            "profile_digest": profile_digest(args.app, profile),
            "version": version,
        }
    )
    if args.manifest:
        write_json(Path(args.manifest), result)
    append_github_outputs(
        {
            "input_archive_sha256": archive_sha,
            "validated_archive_sha256": validated_sha,
            "tree_sha256": result["application"]["tree_sha256"],
            "main_executable_sha256": result["application"]["main_executable_sha256"],
        }
    )
    print(json.dumps(result, indent=2, sort_keys=True))


def parse_keychains(output: str) -> list[str]:
    keychains: list[str] = []
    for line in output.splitlines():
        match = re.search(r'"([^"]+)"', line)
        value = match.group(1) if match else line.strip()
        if value:
            keychains.append(value)
    return keychains


def imported_identity(keychain: Path) -> str:
    result = run(
        ["security", "find-identity", "-v", "-p", "codesigning", str(keychain)],
        capture=True,
    )
    identities = re.findall(r'"(Developer ID Application: [^"]+)"', result.stdout)
    identities = sorted(set(identities))
    if len(identities) != 1:
        fail(f"Expected exactly one Developer ID Application identity, found {len(identities)}.")
    return identities[0]


def parse_codesign_plist(payload: bytes) -> Any | None:
    xml_index = payload.find(b"<?xml")
    binary_index = payload.find(b"bplist")
    indexes = [
        (index, format_name)
        for index, format_name in ((xml_index, "xml"), (binary_index, "binary"))
        if index >= 0
    ]
    if not indexes:
        return None

    start, format_name = min(indexes)
    plist_payload = payload[start:]
    if format_name == "xml":
        closing_tag = b"</plist>"
        end = plist_payload.find(closing_tag)
        if end < 0:
            raise ValueError("XML plist is missing its closing </plist> tag")
        plist_payload = plist_payload[: end + len(closing_tag)]
    return plistlib.loads(plist_payload)


def read_signed_entitlements(app_path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        ["codesign", "-d", "--xml", "--entitlements", "-", str(app_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail("Could not read signed entitlements with codesign.")

    parse_errors: list[Exception] = []
    for payload in (completed.stdout, completed.stderr):
        try:
            value = parse_codesign_plist(payload)
        except Exception as error:
            parse_errors.append(error)
            continue
        if value is None:
            continue
        if not isinstance(value, dict):
            fail("Signed entitlements are not a dictionary.")
        return value

    if parse_errors:
        fail(f"Could not parse signed entitlements: {parse_errors[0]}")
    return {}


def verify_signed_app(
    app_path: Path,
    profile: dict[str, Any],
    expected_team_id: str,
    expected_entitlements: dict[str, Any],
) -> None:
    run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app_path)])
    details = run(["codesign", "-dv", "--verbose=4", str(app_path)], capture=True)
    combined = (details.stdout or "") + (details.stderr or "")
    team_match = re.search(r"^TeamIdentifier=(.+)$", combined, re.MULTILINE)
    if not team_match or team_match.group(1).strip() != expected_team_id:
        fail("Signed application TeamIdentifier does not match APPLE_TEAM_ID.")
    identifier_match = re.search(r"^Identifier=(.+)$", combined, re.MULTILINE)
    if not identifier_match or identifier_match.group(1).strip() != profile["bundle_identifier"]:
        fail("Signed application identifier does not match the profile.")
    if "runtime" not in combined:
        fail("Signed application does not have Hardened Runtime enabled.")
    actual_entitlements = read_signed_entitlements(app_path)
    if actual_entitlements != expected_entitlements:
        fail(
            "Signed entitlements do not match broker policy. "
            f"Expected {expected_entitlements}, got {actual_entitlements}."
        )


def notary_submit(path: Path, apple_id: str, team_id: str, password: str) -> None:
    run(
        [
            "xcrun",
            "notarytool",
            "submit",
            str(path),
            "--apple-id",
            apple_id,
            "--team-id",
            team_id,
            "--password",
            password,
            "--wait",
        ],
        display=False,
    )


def checksum_file(path: Path) -> Path:
    checksum = path.with_name(path.name + ".sha256")
    checksum.write_text(f"{sha256_file(path)}  {path.name}\n", encoding="utf-8")
    return checksum


def compare_executable(reference: Path, candidate_app: Path, executable: str) -> None:
    candidate = candidate_app / "Contents" / "MacOS" / executable
    if not candidate.is_file():
        fail("Packaged artifact is missing the signed main executable.")
    if sha256_file(reference) != sha256_file(candidate):
        fail("Packaged artifact contains a different main executable.")


def create_and_verify_zip(
    app_path: Path,
    output: Path,
    profile: dict[str, Any],
    reference_executable: Path,
) -> None:
    run(["ditto", "-c", "-k", "--norsrc", "--keepParent", str(app_path), str(output)])
    with tempfile.TemporaryDirectory(prefix="broker-verify-zip-") as temporary:
        extracted = Path(temporary)
        run(["ditto", "-x", "-k", str(output), str(extracted)])
        candidate = extracted / profile["bundle_name"]
        compare_executable(reference_executable, candidate, profile["executable"])
        run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(candidate)])
        run(["xcrun", "stapler", "validate", str(candidate)])


def create_and_verify_dmg(
    app_path: Path,
    output: Path,
    profile: dict[str, Any],
    identity: str,
    apple_id: str,
    team_id: str,
    password: str,
    reference_executable: Path,
) -> None:
    with tempfile.TemporaryDirectory(prefix="broker-dmg-") as temporary:
        temporary_path = Path(temporary)
        staging = temporary_path / "staging"
        staging.mkdir()
        run(["ditto", str(app_path), str(staging / profile["bundle_name"])])
        os.symlink("/Applications", staging / "Applications")
        run(
            [
                "hdiutil",
                "create",
                "-volname",
                profile["dmg_volume_name"],
                "-srcfolder",
                str(staging),
                "-ov",
                "-format",
                "UDZO",
                str(output),
            ]
        )
        run(["codesign", "--force", "--sign", identity, "--timestamp", str(output)])
        run(["codesign", "--verify", "--strict", "--verbose=2", str(output)])
        run(["hdiutil", "verify", str(output)])
        notary_submit(output, apple_id, team_id, password)
        run(["xcrun", "stapler", "staple", str(output)])
        run(["xcrun", "stapler", "validate", str(output)])
        run(
            [
                "spctl",
                "--assess",
                "--type",
                "open",
                "--context",
                "context:primary-signature",
                "--verbose=4",
                str(output),
            ]
        )

        mount_point = temporary_path / "mount"
        mount_point.mkdir()
        attached = False
        try:
            run(
                [
                    "hdiutil",
                    "attach",
                    str(output),
                    "-nobrowse",
                    "-readonly",
                    "-mountpoint",
                    str(mount_point),
                    "-quiet",
                ]
            )
            attached = True
            candidate = mount_point / profile["bundle_name"]
            compare_executable(reference_executable, candidate, profile["executable"])
            run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(candidate)])
            run(["xcrun", "stapler", "validate", str(candidate)])
        finally:
            if attached:
                run(["hdiutil", "detach", str(mount_point), "-quiet"], check=False)


def command_sign(args: argparse.Namespace) -> None:
    require_tools(
        [
            "codesign",
            "ditto",
            "hdiutil",
            "openssl",
            "security",
            "spctl",
            "xcrun",
        ]
    )
    version = validate_tag(f"v{args.version}")
    profile = get_profile(args.app)
    app_root = Path(args.app_root).resolve()
    app_path = app_root / profile["bundle_name"]
    pre_sign = validate_app_tree(app_path, profile, version, require_unsigned=True)
    if pre_sign["tree_sha256"] != args.expected_tree_sha:
        fail("Application tree changed after secretless preflight.")
    if profile_digest(args.app, profile) != args.profile_digest:
        fail("Broker profile digest does not match the resolver output.")

    required_environment = [
        "MACOS_CERTIFICATE",
        "MACOS_CERTIFICATE_PWD",
        "APPLE_ID",
        "APPLE_TEAM_ID",
        "APPLE_APP_PASSWORD",
    ]
    missing = [name for name in required_environment if not os.environ.get(name)]
    if missing:
        fail(f"Signing environment is missing secrets: {', '.join(missing)}")
    certificate_data = os.environ["MACOS_CERTIFICATE"]
    certificate_password = os.environ["MACOS_CERTIFICATE_PWD"]
    apple_id = os.environ["APPLE_ID"]
    team_id = os.environ["APPLE_TEAM_ID"]
    apple_password = os.environ["APPLE_APP_PASSWORD"]

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        fail(f"Signing output directory must be empty: {output_dir}")

    original_keychains = parse_keychains(
        run(["security", "list-keychains", "-d", "user"], capture=True).stdout
    )
    with tempfile.TemporaryDirectory(prefix="broker-sign-") as temporary:
        temporary_path = Path(temporary)
        certificate_path = temporary_path / "certificate.p12"
        keychain_path = temporary_path / "notarization.keychain-db"
        keychain_password = secrets.token_urlsafe(32)
        try:
            try:
                decoded = base64.b64decode(certificate_data, validate=True)
            except ValueError as error:
                fail(f"MACOS_CERTIFICATE is not valid base64: {error}")
            certificate_path.write_bytes(decoded)
            certificate_path.chmod(0o600)

            run(["security", "create-keychain", "-p", keychain_password, str(keychain_path)])
            run(["security", "set-keychain-settings", "-lut", "21600", str(keychain_path)])
            run(["security", "unlock-keychain", "-p", keychain_password, str(keychain_path)])
            run(
                [
                    "security",
                    "import",
                    str(certificate_path),
                    "-P",
                    certificate_password,
                    "-A",
                    "-t",
                    "cert",
                    "-f",
                    "pkcs12",
                    "-k",
                    str(keychain_path),
                    "-T",
                    "/usr/bin/codesign",
                    "-T",
                    "/usr/bin/security",
                ],
                display=False,
            )
            run(
                [
                    "security",
                    "set-key-partition-list",
                    "-S",
                    "apple-tool:,apple:",
                    "-k",
                    keychain_password,
                    str(keychain_path),
                ],
                display=False,
            )
            run(
                ["security", "list-keychains", "-d", "user", "-s", str(keychain_path)]
                + original_keychains
            )
            identity = imported_identity(keychain_path)

            entitlement_path = safe_profile_path(profile["entitlements"])
            with entitlement_path.open("rb") as handle:
                expected_entitlements = plistlib.load(handle)
            run(
                [
                    "codesign",
                    "--force",
                    "--sign",
                    identity,
                    "--identifier",
                    profile["bundle_identifier"],
                    "--options",
                    "runtime",
                    "--timestamp",
                    "--entitlements",
                    str(entitlement_path),
                    str(app_path),
                ]
            )
            verify_signed_app(app_path, profile, team_id, expected_entitlements)

            submission = temporary_path / "app-notarization.zip"
            run(
                [
                    "ditto",
                    "-c",
                    "-k",
                    "--norsrc",
                    "--keepParent",
                    str(app_path),
                    str(submission),
                ]
            )
            notary_submit(submission, apple_id, team_id, apple_password)
            run(["xcrun", "stapler", "staple", str(app_path)])
            run(["xcrun", "stapler", "validate", str(app_path)])
            verify_signed_app(app_path, profile, team_id, expected_entitlements)
            run(["spctl", "--assess", "--type", "execute", "--verbose=4", str(app_path)])

            reference_executable = app_path / "Contents" / "MacOS" / profile["executable"]
            artifacts: list[dict[str, Any]] = []
            for artifact in profile["artifacts"]:
                name = artifact["name"].format(version=version)
                destination = output_dir / name
                if artifact["type"] == "zip":
                    create_and_verify_zip(app_path, destination, profile, reference_executable)
                else:
                    create_and_verify_dmg(
                        app_path,
                        destination,
                        profile,
                        identity,
                        apple_id,
                        team_id,
                        apple_password,
                        reference_executable,
                    )
                checksum = checksum_file(destination)
                artifacts.append(
                    {
                        "name": destination.name,
                        "sha256": sha256_file(destination),
                        "bytes": destination.stat().st_size,
                        "checksum": checksum.name,
                    }
                )

            preflight_manifest = Path(args.preflight_manifest).resolve()
            if not preflight_manifest.is_file():
                fail("Preflight manifest is missing.")
            shutil.copy2(preflight_manifest, output_dir / "preflight-manifest.json")
            provenance = {
                "schema_version": 1,
                "profile": args.app,
                "profile_digest": args.profile_digest,
                "request_id": args.request_id,
                "version": version,
                "broker": {
                    "repository": args.broker_repository,
                    "commit_sha": args.broker_commit_sha,
                    "run_id": args.run_id,
                    "run_attempt": args.run_attempt,
                },
                "source": {
                    "repository": args.source_repository,
                    "repository_id": int(args.source_repository_id),
                    "tag": args.source_tag,
                    "ref_target_sha": args.source_ref_sha,
                    "tag_object_sha": args.source_tag_object_sha or None,
                    "commit_sha": args.source_commit_sha,
                },
                "unsigned_application": pre_sign,
                "signed_application": {
                    "bundle_identifier": profile["bundle_identifier"],
                    "team_id": team_id,
                    "main_executable_sha256": sha256_file(reference_executable),
                },
                "artifacts": artifacts,
            }
            write_json(output_dir / "provenance.json", provenance)
        finally:
            if original_keychains:
                run(
                    ["security", "list-keychains", "-d", "user", "-s"] + original_keychains,
                    check=False,
                    display=False,
                )
            if keychain_path.exists():
                run(
                    ["security", "delete-keychain", str(keychain_path)],
                    check=False,
                    display=False,
                )
            certificate_path.unlink(missing_ok=True)
            for secret_name in required_environment:
                os.environ.pop(secret_name, None)

    print(f"Notarized artifacts are in {output_dir}.")


def command_profiles(_: argparse.Namespace) -> None:
    profiles = load_profiles()
    for name in sorted(profiles):
        profile = profiles[name]
        print(
            f"{name}: {profile['repository']} ({profile['repository_id']}) "
            f"{profile['bundle_identifier']}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve = subparsers.add_parser("resolve", help="Resolve a profile tag to an immutable commit")
    resolve.add_argument("--app", required=True)
    resolve.add_argument("--tag", required=True)
    resolve.add_argument("--request-id", default="")
    resolve.add_argument("--expect-sha", default="")
    resolve.add_argument("--output")
    resolve.set_defaults(function=command_resolve)

    build = subparsers.add_parser("build", help="Build an unsigned application")
    build.add_argument("--app", required=True)
    build.add_argument("--source", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--commit-sha", required=True)
    build.add_argument("--build-number", required=True)
    build.add_argument("--output", required=True)
    build.set_defaults(function=command_build)

    validate = subparsers.add_parser("validate", help="Validate and sanitize an unsigned bundle")
    validate.add_argument("--app", required=True)
    validate.add_argument("--version", required=True)
    validate.add_argument("--archive", required=True)
    validate.add_argument("--extract-to", required=True)
    validate.add_argument("--validated-archive")
    validate.add_argument("--manifest")
    validate.add_argument("--expected-archive-sha", default="")
    validate.add_argument("--expected-tree-sha", default="")
    validate.set_defaults(function=command_validate)

    sign = subparsers.add_parser("sign", help="Sign, notarize, and package a validated bundle")
    sign.add_argument("--app", required=True)
    sign.add_argument("--version", required=True)
    sign.add_argument("--app-root", required=True)
    sign.add_argument("--expected-tree-sha", required=True)
    sign.add_argument("--profile-digest", required=True)
    sign.add_argument("--preflight-manifest", required=True)
    sign.add_argument("--output-dir", required=True)
    sign.add_argument("--request-id", required=True)
    sign.add_argument("--source-repository", required=True)
    sign.add_argument("--source-repository-id", required=True)
    sign.add_argument("--source-tag", required=True)
    sign.add_argument("--source-ref-sha", required=True)
    sign.add_argument("--source-tag-object-sha", default="")
    sign.add_argument("--source-commit-sha", required=True)
    sign.add_argument("--broker-repository", required=True)
    sign.add_argument("--broker-commit-sha", required=True)
    sign.add_argument("--run-id", required=True)
    sign.add_argument("--run-attempt", required=True)
    sign.set_defaults(function=command_sign)

    profiles = subparsers.add_parser("profiles", help="Validate and list broker profiles")
    profiles.set_defaults(function=command_profiles)
    return parser


def main() -> int:
    try:
        arguments = build_parser().parse_args()
        arguments.function(arguments)
        return 0
    except BrokerError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
