#!/usr/bin/env python3
"""Broker-owned build, validation, signing, and notarization operations."""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import plistlib
import re
import secrets
import shlex
import shutil
import stat
import struct
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
# A nested bundle is rejected for every profile unless a reviewed profile names
# it exactly. ".appex" is an app extension, ".driver" is a CoreAudio HAL plug-in
# bundle and ".systemextension" is a System Extension; all three are listed here
# so that an undeclared one is rejected like any other nested bundle, and allowed
# only when a profile pins it through a `plugin_bundle` declaration.
NESTED_BUNDLE_SUFFIXES = (
    ".app",
    ".appex",
    ".bundle",
    ".driver",
    ".framework",
    ".systemextension",
    ".xpc",
)
# Slice names a profile may declare in `architectures`. Every profile has been
# arm64-only, but a system audio HAL plug-in has to load on Intel Macs too, so a
# profile may declare a universal binary from this closed set. The set is closed
# because `lipo -archs` output is compared against it exactly.
ALLOWED_ARCHITECTURES = ("arm64", "x86_64")
# Bundle suffixes a profile may pin as a `plugin_bundle`, each mapped to the one
# CFBundlePackageType it may carry. Kept to the three kinds of loadable code an
# application is allowed to embed here — an app extension, a CoreAudio HAL
# plug-in and a System Extension — so the allowance cannot be used to smuggle an
# undeclared .app or .framework past the nested-bundle check by relabelling it.
# An app extension is hosted out of process by its owner (Safari, in the case of
# a web extension), which is why it carries the XPC bundle type rather than a
# plain "BNDL". The mapping is exact rather than two independent sets, so a
# bundle cannot claim the suffix of one kind and the package type of the other.
# An application ("APPL") is never embeddable and appears in neither.
PLUGIN_BUNDLE_PACKAGE_TYPES = {".appex": "XPC!", ".driver": "BNDL", ".systemextension": "SYSX"}
PLUGIN_BUNDLE_SUFFIXES = tuple(PLUGIN_BUNDLE_PACKAGE_TYPES)
TEAM_ID_PATTERN = re.compile(r"^[A-Z0-9]{10}$")
CODE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
BUNDLE_RELATIVE_PATH_PATTERN = re.compile(
    r"^Contents/[A-Za-z0-9][A-Za-z0-9 ._+-]*(?:/[A-Za-z0-9][A-Za-z0-9 ._+-]*)*$"
)
LAUNCH_DAEMON_DIRECTORY = "Contents/Library/LaunchDaemons"
LAUNCH_JOB_DIRECTORIES = (LAUNCH_DAEMON_DIRECTORY, "Contents/Library/LaunchAgents")
# macOS filesystems are case-insensitive by default, so a differently-cased
# spelling names the same directory at runtime. Match with casefold(), which
# implements the full Unicode fold APFS uses; str.lower() would miss folds such
# as U+017F LATIN SMALL LETTER LONG S onto "s".
LAUNCH_JOB_PREFIXES = tuple(directory.casefold() for directory in LAUNCH_JOB_DIRECTORIES)
LAUNCH_DAEMON_FIELDS = {"path", "label", "mach_services"}
# A root job definition is policy, so the plist may carry only keys a reviewed
# profile pins. Everything else -- RunAtLoad, KeepAlive, EnvironmentVariables,
# Sockets, StandardOutPath -- is rejected rather than signed unreviewed.
LAUNCH_DAEMON_REQUIRED_KEYS = {"Label", "BundleProgram"}
# Entitlements macOS treats as "restricted": AMFI refuses to launch a binary
# carrying one unless the bundle embeds a provisioning profile that grants it.
# Signing and notarization both succeed without the profile, so an app that
# needs one and ships without it passes every check here and then fails on the
# user's machine with a bare "Launch failed" -- which is exactly what happened
# to OpenLens v0.1.0 and v0.1.1. Membership is what makes a profile mandatory
# below, so the set is deliberately small and only grows with evidence.
RESTRICTED_ENTITLEMENTS = frozenset(
    {
        "com.apple.developer.driverkit",
        "com.apple.developer.endpoint-security.client",
        "com.apple.developer.hypervisor",
        "com.apple.developer.networking.networkextension",
        "com.apple.developer.system-extension.install",
        "com.apple.vm.networking",
    }
)
PROVISIONING_PROFILE_FIELDS = {"path"}
# Where an application bundle carries its profile. Apple fixes both the name and
# the location; nothing else is read at launch.
PROVISIONING_PROFILE_PATH = "Contents/embedded.provisionprofile"


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
        "better-kampfinsel-xcode",
        "printfilemanager-xcode",
        "threemfquicklook-xcode",
        "md2loop-xcode",
        "openconnct-make",
        "opendefendrwatchr-swiftpm",
        "openlens-xcode",
        "openswitchr-swiftpm",
        "openwritr-swiftpm",
        "ptionsplus-xcode",
        "spacemender-xcode",
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
        architectures = profile["architectures"]
        if (
            not isinstance(architectures, list)
            or not architectures
            or len(architectures) != len(set(architectures))
            or any(slice_name not in ALLOWED_ARCHITECTURES for slice_name in architectures)
        ):
            fail(
                f"Profile {name} must declare architectures as a non-empty, duplicate-free "
                f"subset of {list(ALLOWED_ARCHITECTURES)}."
            )
        entitlement_path = safe_profile_path(profile["entitlements"])
        with entitlement_path.open("rb") as handle:
            entitlements = plistlib.load(handle)
        if not isinstance(entitlements, dict):
            fail(f"Profile {name} entitlements must be a plist dictionary.")
        validate_provisioning_policy(name, profile, entitlements)
        if "dependency_lock" in profile:
            safe_profile_path(profile["dependency_lock"])
        if "team_id" in profile and not TEAM_ID_PATTERN.fullmatch(str(profile["team_id"])):
            fail(f"Profile {name} has an invalid Apple Team ID.")
        validate_nested_executable_policy(name, profile)
        validate_nested_resource_bundle_policy(name, profile)
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


def nested_executables(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return profile.get("nested_executables", [])


def nested_resource_bundles(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return profile.get("nested_resource_bundles", [])


def restricted_entitlements(entitlements: dict[str, Any]) -> list[str]:
    """The restricted entitlements a plist claims, in a stable order."""
    return sorted(RESTRICTED_ENTITLEMENTS.intersection(entitlements))


def validate_provisioning_policy(
    name: str, profile: dict[str, Any], entitlements: dict[str, Any]
) -> None:
    """Refuse a profile that would sign an app macOS then refuses to launch.

    A restricted entitlement is only honoured when the bundle embeds a matching
    provisioning profile. Nothing later in this pipeline notices its absence:
    codesign is happy, notarization is happy, Gatekeeper is happy, and the app
    dies at exec. So the requirement is enforced here, where a reviewer sees it,
    rather than discovered by whoever downloads the release.
    """
    declared = profile.get("provisioning_profile")
    if declared is not None:
        if not isinstance(declared, dict):
            fail(f"Profile {name} must declare provisioning_profile as an object.")
        unknown = set(declared) - PROVISIONING_PROFILE_FIELDS
        if unknown:
            fail(
                f"Profile {name} provisioning_profile has unsupported fields: "
                f"{', '.join(sorted(unknown))}."
            )
        missing = PROVISIONING_PROFILE_FIELDS - set(declared)
        if missing:
            fail(
                f"Profile {name} provisioning_profile is missing fields: "
                f"{', '.join(sorted(missing))}."
            )
        if not safe_profile_path(str(declared["path"])).is_file():
            fail(f"Profile {name} provisioning_profile path does not exist.")
        if "team_id" not in profile:
            # The embedded profile is checked against the signing team, so a
            # profile that ships one has to say which team it belongs to.
            fail(f"Profile {name} must declare team_id to embed a provisioning profile.")

    restricted = restricted_entitlements(entitlements)
    if restricted and declared is None:
        fail(
            f"Profile {name} claims restricted entitlements without a provisioning "
            f"profile, so the signed app would not launch: {', '.join(restricted)}."
        )

    # Only the application bundle gets a profile. A nested executable that needs
    # one would need its own, which is not supported, so it is rejected outright
    # instead of being signed into something that cannot run.
    for spec in nested_executables(profile):
        with safe_profile_path(spec["entitlements"]).open("rb") as handle:
            nested = plistlib.load(handle)
        if not isinstance(nested, dict):
            fail(f"Profile {name} nested entitlements must be a plist dictionary.")
        nested_restricted = restricted_entitlements(nested)
        if nested_restricted:
            fail(
                f"Profile {name} nested executable {spec['identifier']} claims restricted "
                f"entitlements, which the broker cannot provision: "
                f"{', '.join(nested_restricted)}."
            )


def render_expected_value(template: str, profile: dict[str, Any], spec: dict[str, Any]) -> str:
    """Expand the declarative placeholders allowed in embedded Info.plist policy."""
    try:
        return template.format(
            team_id=profile.get("team_id", ""),
            bundle_identifier=profile["bundle_identifier"],
            identifier=spec["identifier"],
        )
    except (IndexError, KeyError, ValueError) as error:
        fail(f"Embedded Info.plist expectation uses an unsupported placeholder: {error}")
    return template


def validate_nested_resource_bundle_policy(name: str, profile: dict[str, Any]) -> None:
    """Validate declarations of nested bundles that carry no code.

    SwiftPM emits a resource bundle for any dependency shipping a privacy manifest, so an app can
    contain a nested bundle it never asked for. Declaring one here only lifts the nested-bundle
    check for that exact path. Everything inside it is still policed by the preflight walk: a
    Mach-O file is rejected because it is not in `declared_code`, an executable bit is rejected the
    same way, a symlink is rejected outright, and a further nested bundle inside it must itself be
    declared. Declaring a resource bundle therefore cannot become a way to smuggle in code.
    """
    specs = profile.get("nested_resource_bundles")
    if specs is None:
        return
    if not isinstance(specs, list) or not specs:
        fail(f"Profile {name} must declare nested_resource_bundles as a non-empty list or omit it.")

    seen: set[str] = set()
    for spec in specs:
        if not isinstance(spec, dict):
            fail(f"Profile {name} has a nested resource bundle entry that is not an object.")
        unknown = set(spec) - {"path"}
        if unknown:
            fail(
                f"Profile {name} nested resource bundle has unsupported fields: "
                f"{', '.join(sorted(unknown))}"
            )
        path = spec.get("path")
        if not isinstance(path, str) or not BUNDLE_RELATIVE_PATH_PATTERN.fullmatch(path):
            fail(f"Profile {name} has an unsafe nested resource bundle path: {path!r}")
        if not path.casefold().endswith(NESTED_BUNDLE_SUFFIXES):
            fail(f"Profile {name} declares a resource bundle that is not a bundle: {path}")
        if path in seen:
            fail(f"Profile {name} declares a duplicate resource bundle path: {path}")
        seen.add(path)


def validate_nested_executable_policy(name: str, profile: dict[str, Any]) -> None:
    specs = profile.get("nested_executables")
    if specs is None:
        return
    if not isinstance(specs, list) or not specs:
        fail(f"Profile {name} must declare nested_executables as a non-empty list or omit it.")
    if "team_id" not in profile:
        fail(f"Profile {name} must declare team_id before it may ship nested executables.")

    allowed_fields = {
        "path",
        "identifier",
        "entitlements",
        "embedded_info_plist",
        "launch_daemon",
        "plugin_bundle",
    }
    required_fields = {"path", "identifier", "entitlements"}
    claimed = {f"Contents/MacOS/{profile['executable']}"}
    for spec in specs:
        if not isinstance(spec, dict):
            fail(f"Profile {name} has a nested executable entry that is not an object.")
        unknown = set(spec) - allowed_fields
        if unknown:
            fail(f"Profile {name} nested executable has unsupported fields: {', '.join(sorted(unknown))}")
        missing = required_fields - set(spec)
        if missing:
            fail(f"Profile {name} nested executable is missing fields: {', '.join(sorted(missing))}")

        path = spec["path"]
        if not isinstance(path, str) or not BUNDLE_RELATIVE_PATH_PATTERN.fullmatch(path):
            fail(f"Profile {name} has an unsafe nested executable path: {path!r}")
        if path in claimed:
            fail(f"Profile {name} declares a duplicate bundle path: {path}")
        claimed.add(path)

        if not CODE_IDENTIFIER_PATTERN.fullmatch(str(spec["identifier"])):
            fail(f"Profile {name} has an invalid nested code identifier: {spec['identifier']!r}")
        entitlement_path = safe_profile_path(spec["entitlements"])
        with entitlement_path.open("rb") as handle:
            entitlements = plistlib.load(handle)
        if not isinstance(entitlements, dict):
            fail(f"Profile {name} nested entitlements must be a plist dictionary.")

        expectations = spec.get("embedded_info_plist", {})
        if not isinstance(expectations, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in expectations.items()
        ):
            fail(f"Profile {name} embedded_info_plist must map string keys to string values.")
        for template in expectations.values():
            render_expected_value(template, profile, spec)

        plugin = spec.get("plugin_bundle")
        if plugin is not None:
            # A HAL plug-in is a bundle, not a launch daemon: coreaudiod loads it,
            # launchd never sees it. The two shapes are mutually exclusive so a
            # profile cannot claim daemon semantics for a plug-in or vice versa.
            if "launch_daemon" in spec:
                fail(
                    f"Profile {name} nested executable cannot declare both plugin_bundle "
                    "and launch_daemon."
                )
            if not isinstance(plugin, dict) or set(plugin) != {"path", "identifier", "package_type"}:
                fail(
                    f"Profile {name} plugin_bundle must declare exactly path, identifier, "
                    "and package_type."
                )
            plugin_path = plugin["path"]
            if not isinstance(plugin_path, str) or not BUNDLE_RELATIVE_PATH_PATTERN.fullmatch(plugin_path):
                fail(f"Profile {name} has an unsafe plugin_bundle path: {plugin_path!r}")
            plugin_suffix = next(
                (
                    suffix
                    for suffix in PLUGIN_BUNDLE_SUFFIXES
                    if PurePosixPath(plugin_path).name.casefold().endswith(suffix)
                ),
                None,
            )
            if plugin_suffix is None:
                fail(
                    f"Profile {name} plugin_bundle must be a plug-in bundle ending in one of "
                    f"{', '.join(PLUGIN_BUNDLE_SUFFIXES)}."
                )
            # The declared executable must be the plug-in bundle's own Mach-O, so the
            # bytes preflight pins are exactly the ones the signing job seals when it
            # signs the enclosing bundle inside-out.
            expected_prefix = f"{plugin_path}/Contents/MacOS/"
            if not path.startswith(expected_prefix):
                fail(
                    f"Profile {name} plugin_bundle executable must live under {expected_prefix}."
                )
            expected_package_type = PLUGIN_BUNDLE_PACKAGE_TYPES[plugin_suffix]
            if plugin["package_type"] != expected_package_type:
                fail(
                    f"Profile {name} plugin_bundle {plugin_suffix} must declare package_type "
                    f"{expected_package_type}."
                )
            if not CODE_IDENTIFIER_PATTERN.fullmatch(str(plugin["identifier"])):
                fail(f"Profile {name} has an invalid plugin_bundle identifier: {plugin['identifier']!r}")
            if plugin_path in claimed:
                fail(f"Profile {name} declares a duplicate bundle path: {plugin_path}")
            claimed.add(plugin_path)

        daemon = spec.get("launch_daemon")
        if daemon is None:
            continue
        if not isinstance(daemon, dict) or not {"path", "label"} <= set(daemon) <= LAUNCH_DAEMON_FIELDS:
            fail(
                f"Profile {name} launch_daemon must declare path and label, "
                f"and may only add mach_services."
            )
        daemon_path = daemon["path"]
        if not isinstance(daemon_path, str) or not BUNDLE_RELATIVE_PATH_PATTERN.fullmatch(daemon_path):
            fail(f"Profile {name} has an unsafe launch daemon path: {daemon_path!r}")
        if PurePosixPath(daemon_path).parent.as_posix() != LAUNCH_DAEMON_DIRECTORY:
            fail(f"Profile {name} launch daemon must live in {LAUNCH_DAEMON_DIRECTORY}.")
        if daemon_path in claimed:
            fail(f"Profile {name} declares a duplicate bundle path: {daemon_path}")
        claimed.add(daemon_path)
        if not CODE_IDENTIFIER_PATTERN.fullmatch(str(daemon["label"])):
            fail(f"Profile {name} has an invalid launch daemon label: {daemon['label']!r}")
        services = daemon.get("mach_services")
        if services is None:
            continue
        if not isinstance(services, list) or not services:
            fail(f"Profile {name} launch daemon mach_services must be a non-empty list.")
        if len(set(services)) != len(services):
            fail(f"Profile {name} launch daemon declares a duplicate Mach service.")
        for service in services:
            if not isinstance(service, str) or not CODE_IDENTIFIER_PATTERN.fullmatch(service):
                fail(f"Profile {name} has an invalid Mach service name: {service!r}")


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
    for spec in nested_executables(profile):
        paths.append(safe_profile_path(spec["entitlements"]))
    digest.update(app.encode("utf-8") + b"\0")
    for path in sorted(set(paths)):
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


def xcodebuild_settings(profile: dict[str, Any], version: str, build_number: str) -> list[str]:
    settings = [
        f"MARKETING_VERSION={version}",
        f"CURRENT_PROJECT_VERSION={build_number}",
        "ENABLE_HARDENED_RUNTIME=YES",
        "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO",
        "CODE_SIGNING_ALLOWED=NO",
        "CODE_SIGNING_REQUIRED=NO",
        f"ARCHS={' '.join(profile['architectures'])}",
        "ONLY_ACTIVE_ARCH=NO",
    ]
    if "team_id" in profile:
        # A Team ID is public and is not a signing credential, so it is declared in the
        # profile rather than exposed to the secretless build job as an Apple secret.
        # Nested helpers need it while compiling to embed a correct client requirement.
        settings.append(f"DEVELOPMENT_TEAM={profile['team_id']}")
    return settings


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
        ]
        + xcodebuild_settings(profile, version, build_number),
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


def assemble_opendefendrwatchr(
    source: Path, work: Path, profile: dict[str, Any], version: str
) -> Path:
    executable = swift_build(source, "OpenDefendrWatchr", require_lock=False)
    app = work / profile["bundle_name"]
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    # The app ships no resources, but preflight requires the directory to exist.
    (app / "Contents" / "Resources").mkdir(parents=True)
    shutil.copy2(executable, macos / profile["executable"])
    info_path = app / "Contents" / "Info.plist"
    shutil.copy2(ensure_source_file(source, "Sources/OpenDefendrWatchr/Info.plist"), info_path)
    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    # The source Info.plist carries __VERSION__ placeholders that only the app's own
    # build script substitutes, so the broker has to fill them in itself.
    info.update(
        {
            "CFBundleExecutable": profile["executable"],
            "CFBundleDisplayName": profile["bundle_display_name"],
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": version,
            "LSMinimumSystemVersion": profile["minimum_system_version"],
            "NSHighResolutionCapable": True,
        }
    )
    # A menu bar app that loses LSUIElement would ship with a Dock icon and a
    # focus-stealing window, so refuse to sign that rather than notarise it.
    if info.get("LSUIElement") is not True:
        fail("OpenDefendrWatchr must stay menu-bar-only: LSUIElement is not true.")
    with info_path.open("wb") as handle:
        plistlib.dump(info, handle, sort_keys=True)
    return app


def assemble_openswitchr(source: Path, work: Path, profile: dict[str, Any]) -> Path:
    executable = swift_build(source, "OpenSwitchr", require_lock=False)
    app = work / profile["bundle_name"]
    macos = app / "Contents" / "MacOS"
    resources = app / "Contents" / "Resources"
    macos.mkdir(parents=True)
    resources.mkdir(parents=True)
    shutil.copy2(executable, macos / profile["executable"])
    info_path = app / "Contents" / "Info.plist"
    shutil.copy2(ensure_source_file(source, "Info.plist"), info_path)
    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    info.update(
        {
            "CFBundleExecutable": profile["executable"],
            "CFBundlePackageType": profile["package_type"],
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
        ]
        + xcodebuild_settings(profile, version, build_number),
        cwd=source,
    )
    return derived_data / "Build" / "Products" / "Release" / profile["bundle_name"]


def build_openlens(
    source: Path, work: Path, profile: dict[str, Any], version: str, build_number: str
) -> Path:
    # Built from the committed project for the same reason as build_spacemender:
    # OpenLens generates its .xcodeproj with XcodeGen, which is not on the runner
    # image, so the project is committed and this adapter drives it directly. The
    # scheme builds the app and its camera system extension and embeds the latter
    # under Contents/Library/SystemExtensions; preflight pins that path.
    ensure_source_file(source, "OpenLens.xcodeproj/project.pbxproj")
    derived_data = work / "DerivedData"
    run(
        [
            "xcodebuild",
            "-project",
            "OpenLens.xcodeproj",
            "-scheme",
            "OpenLens",
            "-configuration",
            "Release",
            "-derivedDataPath",
            str(derived_data),
            "clean",
            "build",
        ]
        + xcodebuild_settings(profile, version, build_number),
        cwd=source,
    )
    return derived_data / "Build" / "Products" / "Release" / profile["bundle_name"]


def build_spacemender(
    source: Path, work: Path, profile: dict[str, Any], version: str, build_number: str
) -> Path:
    # Built from the committed project rather than generated from project.yml:
    # the untrusted build job runs only tooling preinstalled on the runner, and
    # XcodeGen is not part of that image. Fetching it here would add an unpinned
    # download to the job that handles third-party source. A committed project
    # that disagrees with the manifest cannot smuggle anything through either,
    # because preflight validates the produced bundle against this profile.
    ensure_source_file(source, "SpaceMender.xcodeproj/project.pbxproj")
    derived_data = work / "DerivedData"
    run(
        [
            "xcodebuild",
            "-project",
            "SpaceMender.xcodeproj",
            "-scheme",
            "SpaceMender",
            "-configuration",
            "Release",
            "-derivedDataPath",
            str(derived_data),
            "clean",
            "build",
        ]
        + xcodebuild_settings(profile, version, build_number),
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


def stamp_bundle_version(app: Path, version: str, build_number: str) -> None:
    # OpenConnct's Makefile installs a static Info.plist, so the broker stamps the
    # release version into the built bundle the same way the xcodebuild adapters pass
    # MARKETING_VERSION and CURRENT_PROJECT_VERSION. Preflight independently checks
    # CFBundleShortVersionString against the resolved tag, so this only lets an honest
    # build satisfy that check; it cannot relax it.
    info_path = app / "Contents" / "Info.plist"
    if info_path.is_symlink() or not info_path.is_file():
        fail("Built application is missing Contents/Info.plist.")
    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    if not isinstance(info, dict):
        fail("Built application Info.plist is not a dictionary.")
    info["CFBundleShortVersionString"] = version
    info["CFBundleVersion"] = build_number
    with info_path.open("wb") as handle:
        plistlib.dump(info, handle)


def build_openconnct(
    source: Path, work: Path, profile: dict[str, Any], version: str, build_number: str
) -> Path:
    # OpenConnct ships no committed .xcodeproj and its app target is not a SwiftPM
    # executable: a SwiftUI binary is linked by swiftc against a C++ DSP static
    # library, and a CoreAudio HAL plug-in is compiled by clang and embedded into the
    # app. Its committed, deterministic build definition is the Makefile, so this
    # adapter drives that the same way build_spacemender drives a committed
    # .xcodeproj. `make` and the compilers it invokes (clang, swiftc, libtool, lipo)
    # all ship with the runner's Xcode; nothing is generated, fetched, or installed,
    # which keeps the untrusted build job on preinstalled tooling only.
    require_tools(["make"])
    ensure_source_file(source, "Makefile")
    dist = work / "dist"
    # UNIVERSAL=1 builds both the arm64 and x86_64 slices — a system audio driver has
    # to load on Intel Macs too — and embed-driver copies the built .driver into the
    # app. DIST_DIR is redirected into the broker work tree so the checked-out source
    # stays pristine. No CODE_SIGN_IDENTITY is exported, so the Makefile's opportunistic
    # signing step finds no identity and leaves the bundle unsigned; that is exactly the
    # linker-signed input preflight requires, and the broker owns all real signing.
    run(["make", "embed-driver", "UNIVERSAL=1", f"DIST_DIR={dist}"], cwd=source)
    app = dist / profile["bundle_name"]
    stamp_bundle_version(app, version, build_number)
    return app


def build_better_kampfinsel(
    source: Path, work: Path, profile: dict[str, Any], version: str, build_number: str
) -> Path:
    # Built from the committed project for the same reason as build_spacemender.
    # The web payload deserves a note of its own: content.js is rolled up from
    # src/modules by a Node script, but the rolled-up file is committed under
    # extension/ and the Xcode target merely copies that directory into the appex.
    # So this adapter needs no Node toolchain and installs no dependencies, which
    # keeps the untrusted build job on preinstalled tooling only. The two payload
    # files are pinned here so a checkout that lost them fails loudly instead of
    # producing a carrier app with an empty extension. The scheme builds the app
    # and its Safari extension and embeds the latter under Contents/PlugIns;
    # preflight pins that path.
    project = "safari/better kampfinsel/better kampfinsel.xcodeproj"
    ensure_source_file(source, f"{project}/project.pbxproj")
    ensure_source_file(source, "extension/manifest.json")
    ensure_source_file(source, "extension/content.js")
    derived_data = work / "DerivedData"
    run(
        [
            "xcodebuild",
            "-project",
            project,
            "-scheme",
            "better kampfinsel",
            "-configuration",
            "Release",
            "-derivedDataPath",
            str(derived_data),
            "clean",
            "build",
        ]
        + xcodebuild_settings(profile, version, build_number),
        cwd=source,
    )
    return derived_data / "Build" / "Products" / "Release" / profile["bundle_name"]


def build_xcodegen_project(
    source: Path,
    work: Path,
    profile: dict[str, Any],
    version: str,
    build_number: str,
    directory: str,
    project: str,
    scheme: str,
) -> Path:
    # Both apps in this repository are generated by XcodeGen from a committed project.yml, and
    # the generated .xcodeproj is committed alongside it. The committed project is what gets
    # built, so the untrusted build job needs no XcodeGen and installs nothing; project.yml is
    # pinned here only so a checkout that lost it fails loudly instead of building something
    # unintended. Each project also depends on ../ThreeMFKit as a local Swift package, so that
    # path is pinned too — without it the build would resolve to nothing and produce a bundle
    # missing its 3MF parsing.
    ensure_source_file(source, f"{directory}/{project}/project.pbxproj")
    ensure_source_file(source, f"{directory}/project.yml")
    ensure_source_file(source, "ThreeMFKit/Package.swift")
    derived_data = work / "DerivedData"
    run(
        [
            "xcodebuild",
            "-project",
            f"{directory}/{project}",
            "-scheme",
            scheme,
            "-configuration",
            "Release",
            "-destination",
            "platform=macOS",
            "-derivedDataPath",
            str(derived_data),
            "clean",
            "build",
        ]
        + xcodebuild_settings(profile, version, build_number),
        cwd=source,
    )
    return derived_data / "Build" / "Products" / "Release" / profile["bundle_name"]


def build_printfilemanager(
    source: Path, work: Path, profile: dict[str, Any], version: str, build_number: str
) -> Path:
    return build_xcodegen_project(
        source,
        work,
        profile,
        version,
        build_number,
        directory="printfilemanager",
        project="PrintFileManager.xcodeproj",
        scheme="PrintFileManager",
    )


def build_threemfquicklook(
    source: Path, work: Path, profile: dict[str, Any], version: str, build_number: str
) -> Path:
    # The scheme embeds both Quick Look extensions under Contents/PlugIns; preflight pins those
    # paths through the profile's nested_executables.
    return build_xcodegen_project(
        source,
        work,
        profile,
        version,
        build_number,
        directory="Quicklook",
        project="ThreeMFQuickLook.xcodeproj",
        scheme="ThreeMFQuickLook",
    )


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
        if adapter == "better-kampfinsel-xcode":
            built_app = build_better_kampfinsel(source, work, profile, version, args.build_number)
        elif adapter == "md2loop-xcode":
            built_app = build_md2loop(source, work, profile, version, args.build_number)
        elif adapter == "openconnct-make":
            built_app = build_openconnct(source, work, profile, version, args.build_number)
        elif adapter == "opendefendrwatchr-swiftpm":
            built_app = assemble_opendefendrwatchr(source, work, profile, version)
        elif adapter == "openlens-xcode":
            built_app = build_openlens(source, work, profile, version, args.build_number)
        elif adapter == "openswitchr-swiftpm":
            built_app = assemble_openswitchr(source, work, profile)
        elif adapter == "openwritr-swiftpm":
            built_app = assemble_openwritr(source, work, profile)
        elif adapter == "printfilemanager-xcode":
            built_app = build_printfilemanager(source, work, profile, version, args.build_number)
        elif adapter == "threemfquicklook-xcode":
            built_app = build_threemfquicklook(source, work, profile, version, args.build_number)
        elif adapter == "ptionsplus-xcode":
            built_app = build_ptionsplus(source, work, profile, version, args.build_number)
        elif adapter == "spacemender-xcode":
            built_app = build_spacemender(source, work, profile, version, args.build_number)
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


THIN_MACHO_LAYOUTS = {
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xcf": (">", True),
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xfe\xed\xfa\xce": (">", False),
}
FAT_MACHO_MAGICS = {b"\xca\xfe\xba\xbe": False, b"\xca\xfe\xba\xbf": True}
MAX_LOAD_COMMANDS = 4096
MAX_LOAD_COMMAND_BYTES = 16 * 1024 * 1024
MAX_EMBEDDED_PLIST_BYTES = 1024 * 1024


def read_bounded(handle: Any, offset: int, size: int, end: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > end:
        fail("Mach-O structure points outside its image.")
    handle.seek(offset)
    payload = handle.read(size)
    if len(payload) != size:
        fail("Mach-O image ended before a declared structure.")
    return payload


def parse_embedded_info_plist(handle: Any, base: int, end: int, depth: int) -> dict[str, Any]:
    if depth > 1:
        fail("Mach-O image nests fat headers.")
    magic = read_bounded(handle, base, 4, end)
    if magic in FAT_MACHO_MAGICS:
        wide = FAT_MACHO_MAGICS[magic]
        count = int.from_bytes(read_bounded(handle, base + 4, 4, end), "big")
        if count != 1:
            fail("Embedded Info.plist policy requires a single-architecture Mach-O image.")
        entry = read_bounded(handle, base + 8, 32 if wide else 20, end)
        width = 8 if wide else 4
        offset = int.from_bytes(entry[8 : 8 + width], "big")
        size = int.from_bytes(entry[8 + width : 8 + 2 * width], "big")
        if size <= 0 or offset + size > end:
            fail("Mach-O fat slice points outside the file.")
        return parse_embedded_info_plist(handle, offset, offset + size, depth + 1)

    if magic not in THIN_MACHO_LAYOUTS:
        fail("File is not a Mach-O image.")
    order, is_64 = THIN_MACHO_LAYOUTS[magic]
    header = read_bounded(handle, base, 32 if is_64 else 28, end)
    ncmds, sizeofcmds = struct.unpack_from(f"{order}II", header, 16)
    if ncmds > MAX_LOAD_COMMANDS or sizeofcmds > MAX_LOAD_COMMAND_BYTES:
        fail("Mach-O image declares an unsupported number of load commands.")

    commands = read_bounded(handle, base + len(header), sizeofcmds, end)
    segment_command = 0x19 if is_64 else 0x01
    nsects_offset, section_start, section_size = (64, 72, 80) if is_64 else (48, 56, 68)
    cursor = 0
    for _ in range(ncmds):
        if cursor + 8 > len(commands):
            fail("Mach-O load commands are truncated.")
        command, command_size = struct.unpack_from(f"{order}II", commands, cursor)
        if command_size < 8 or cursor + command_size > len(commands):
            fail("Mach-O load command has an invalid size.")
        if command == segment_command and commands[cursor + 8 : cursor + 24].rstrip(b"\0") == b"__TEXT":
            if section_start > command_size:
                fail("Mach-O segment command is truncated.")
            nsects = struct.unpack_from(f"{order}I", commands, cursor + nsects_offset)[0]
            for index in range(nsects):
                section = cursor + section_start + index * section_size
                if section + section_size > cursor + command_size:
                    fail("Mach-O segment declares more sections than it contains.")
                if commands[section : section + 16].rstrip(b"\0") != b"__info_plist":
                    continue
                if is_64:
                    size, offset = struct.unpack_from(f"{order}QI", commands, section + 40)
                else:
                    size, offset = struct.unpack_from(f"{order}II", commands, section + 36)
                if size <= 0 or size > MAX_EMBEDDED_PLIST_BYTES:
                    fail("Embedded Info.plist section has an unsupported size.")
                payload = read_bounded(handle, base + offset, size, end)
                try:
                    value = plistlib.loads(payload.rstrip(b"\0"))
                except Exception as error:
                    fail(f"Embedded Info.plist is not a valid property list: {error}")
                if not isinstance(value, dict):
                    fail("Embedded Info.plist must be a dictionary.")
                return value
        cursor += command_size
    fail("Mach-O image does not embed a __TEXT,__info_plist section.")
    return {}


def read_embedded_info_plist(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        return parse_embedded_info_plist(handle, 0, size, 0)


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


def validate_executable_image(path: Path, profile: dict[str, Any], description: str) -> list[str]:
    if path.is_symlink() or not path.is_file():
        fail(f"{description} is missing or unsafe.")
    if not path.stat().st_mode & 0o111:
        fail(f"{description} is not executable.")
    if "Mach-O" not in run(["file", "-b", str(path)], capture=True).stdout:
        fail(f"{description} is not Mach-O.")
    architectures = run(["lipo", "-archs", str(path)], capture=True).stdout.split()
    if sorted(architectures) != sorted(profile["architectures"]):
        fail(
            f"{description} architectures do not match profile: "
            f"expected {profile['architectures']}, got {architectures}"
        )
    return architectures


def validate_launch_daemon(app_path: Path, spec: dict[str, Any]) -> dict[str, Any]:
    daemon = spec["launch_daemon"]
    plist_path = app_path / daemon["path"]
    if plist_path.is_symlink() or not plist_path.is_file():
        fail(f"Declared launch daemon plist is missing or unsafe: {daemon['path']}")
    try:
        with plist_path.open("rb") as handle:
            job = plistlib.load(handle)
    except Exception as error:
        fail(f"Launch daemon plist is invalid: {daemon['path']}: {error}")
    if not isinstance(job, dict):
        fail(f"Launch daemon plist must be a dictionary: {daemon['path']}")
    services = daemon.get("mach_services")
    allowed = set(LAUNCH_DAEMON_REQUIRED_KEYS)
    if services:
        allowed.add("MachServices")
    unreviewed = sorted(set(job) - allowed)
    if unreviewed:
        fail(
            f"Launch daemon plist declares unreviewed keys in {daemon['path']}: "
            f"{', '.join(unreviewed)}"
        )
    missing = sorted(LAUNCH_DAEMON_REQUIRED_KEYS - set(job))
    if missing:
        fail(f"Launch daemon plist is missing required keys in {daemon['path']}: {', '.join(missing)}")
    if job.get("Label") != daemon["label"]:
        fail(
            f"Launch daemon label mismatch in {daemon['path']}: "
            f"expected {daemon['label']!r}, got {job.get('Label')!r}"
        )
    if job.get("BundleProgram") != spec["path"]:
        fail(
            f"Launch daemon BundleProgram mismatch in {daemon['path']}: "
            f"expected {spec['path']!r}, got {job.get('BundleProgram')!r}"
        )
    if services:
        vested = job.get("MachServices")
        if not isinstance(vested, dict):
            fail(f"Launch daemon MachServices must be a dictionary in {daemon['path']}.")
        if sorted(vested) != sorted(services):
            fail(
                f"Launch daemon MachServices mismatch in {daemon['path']}: "
                f"expected {sorted(services)}, got {sorted(vested)}"
            )
        for service, value in vested.items():
            if value is not True:
                fail(
                    f"Launch daemon Mach service {service} must be declared true "
                    f"in {daemon['path']}."
                )
    record = {
        "path": daemon["path"],
        "label": daemon["label"],
        "sha256": sha256_file(plist_path),
    }
    if services:
        record["mach_services"] = sorted(services)
    return record


def validate_plugin_bundle(app_path: Path, spec: dict[str, Any]) -> dict[str, Any]:
    # A HAL plug-in carries its identity in its bundle's Contents/Info.plist, not
    # in a __TEXT,__info_plist section: the Mach-O is a plain clang -bundle with no
    # embedded plist, and it is universal, so parse_embedded_info_plist would reject
    # it anyway. Pin the bundle's declared identity against the profile so the plug-in
    # coreaudiod loads is exactly the one this profile describes.
    plugin = spec["plugin_bundle"]
    bundle_path = app_path / plugin["path"]
    if bundle_path.is_symlink() or not bundle_path.is_dir():
        fail(f"Declared plug-in bundle is missing or unsafe: {plugin['path']}")
    info_path = bundle_path / "Contents" / "Info.plist"
    if info_path.is_symlink() or not info_path.is_file():
        fail(f"Plug-in bundle is missing its Contents/Info.plist: {plugin['path']}")
    try:
        with info_path.open("rb") as handle:
            info = plistlib.load(handle)
    except Exception as error:
        fail(f"Plug-in bundle Info.plist is invalid: {plugin['path']}: {error}")
    if not isinstance(info, dict):
        fail(f"Plug-in bundle Info.plist must be a dictionary: {plugin['path']}")
    checks = {
        "CFBundleIdentifier": plugin["identifier"],
        "CFBundlePackageType": plugin["package_type"],
        "CFBundleExecutable": PurePosixPath(spec["path"]).name,
    }
    for key, expected in checks.items():
        if str(info.get(key, "")) != expected:
            fail(
                f"Plug-in bundle {plugin['path']} Info.plist key {key} mismatch: "
                f"expected {expected!r}, got {info.get(key)!r}"
            )
    return {
        "path": plugin["path"],
        "identifier": plugin["identifier"],
        "package_type": plugin["package_type"],
        "info_plist_sha256": sha256_file(info_path),
    }


def validate_nested_executable(
    app_path: Path, profile: dict[str, Any], spec: dict[str, Any]
) -> dict[str, Any]:
    path = app_path / spec["path"]
    description = f"Declared nested executable {spec['path']}"
    architectures = validate_executable_image(path, profile, description)

    expectations = spec.get("embedded_info_plist", {})
    if expectations:
        embedded = read_embedded_info_plist(path)
        for key, template in sorted(expectations.items()):
            expected = render_expected_value(template, profile, spec)
            if embedded.get(key) != expected:
                fail(
                    f"{description} embedded Info.plist key {key!r} does not match profile "
                    f"policy: expected {expected!r}, got {embedded.get(key)!r}"
                )

    record = {
        "path": spec["path"],
        "identifier": spec["identifier"],
        "architectures": architectures,
        "sha256": sha256_file(path),
    }
    if "launch_daemon" in spec:
        record["launch_daemon"] = validate_launch_daemon(app_path, spec)
    if "plugin_bundle" in spec:
        record["plugin_bundle"] = validate_plugin_bundle(app_path, spec)
    return record


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
    specs = nested_executables(profile)
    declared_code = {main_executable} | {app_path / spec["path"] for spec in specs}
    declared_jobs = {
        app_path / spec["launch_daemon"]["path"] for spec in specs if "launch_daemon" in spec
    }
    # A pinned plug-in bundle is the one nested bundle a profile may ship. Its
    # directory is allowed through the nested-bundle check by exact, case-sensitive
    # path; anything Mach-O or executable inside it is still policed by the checks
    # below because only its declared executable appears in `declared_code`.
    declared_bundles = {
        app_path / spec["plugin_bundle"]["path"] for spec in specs if "plugin_bundle" in spec
    }
    # Resource bundles carry no code. Adding them here lifts only the nested-bundle check; they
    # are deliberately not added to `declared_code`, so any Mach-O or executable file inside one
    # is still rejected by the checks below.
    declared_bundles |= {
        app_path / spec["path"] for spec in nested_resource_bundles(profile)
    }
    for path in app_path.rglob("*"):
        relative = path.relative_to(app_path)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            fail(f"Application contains a symlink or special file: {relative}")
        posix = relative.as_posix().casefold()
        if any(posix.startswith(f"{directory}/") for directory in LAUNCH_JOB_PREFIXES):
            if path not in declared_jobs:
                fail(f"Undeclared launchd job definition: {relative}")
        if path.is_dir() and path != app_path:
            if path.name.casefold().endswith(NESTED_BUNDLE_SUFFIXES) and path not in declared_bundles:
                fail(f"Nested bundles are not allowed for this profile: {relative}")
            continue
        file_count += 1
        total_size += metadata.st_size
        if file_count > profile["max_files"]:
            fail("Application exceeds the file-count limit.")
        if total_size > profile["max_uncompressed_bytes"]:
            fail("Application exceeds the size limit.")
        if path not in declared_code and is_macho(path):
            fail(f"Unexpected nested Mach-O code: {relative}")
        if path not in declared_code and metadata.st_mode & 0o111:
            fail(f"Unexpected executable file: {relative}")
        if path.name == "embedded.provisionprofile" or "_CodeSignature" in relative.parts:
            fail(f"Unsigned input contains signing material: {relative}")

    architectures = validate_executable_image(
        main_executable, profile, "Application main executable"
    )
    nested_records = [validate_nested_executable(app_path, profile, spec) for spec in specs]

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
        "nested_executables": nested_records,
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


def verify_signed_code(
    path: Path,
    *,
    description: str,
    expected_identifier: str,
    expected_team_id: str,
    expected_entitlements: dict[str, Any],
    deep: bool,
) -> None:
    verify = ["codesign", "--verify", "--strict", "--verbose=2", str(path)]
    if deep:
        verify.insert(2, "--deep")
    run(verify)
    details = run(["codesign", "-dv", "--verbose=4", str(path)], capture=True)
    combined = (details.stdout or "") + (details.stderr or "")
    team_match = re.search(r"^TeamIdentifier=(.+)$", combined, re.MULTILINE)
    if not team_match or team_match.group(1).strip() != expected_team_id:
        fail(f"{description} TeamIdentifier does not match APPLE_TEAM_ID.")
    identifier_match = re.search(r"^Identifier=(.+)$", combined, re.MULTILINE)
    if not identifier_match or identifier_match.group(1).strip() != expected_identifier:
        fail(f"{description} identifier does not match the profile.")
    if "runtime" not in combined:
        fail(f"{description} does not have Hardened Runtime enabled.")
    actual_entitlements = read_signed_entitlements(path)
    if actual_entitlements != expected_entitlements:
        fail(
            f"{description} entitlements do not match broker policy. "
            f"Expected {expected_entitlements}, got {actual_entitlements}."
        )


def verify_signed_app(
    app_path: Path,
    profile: dict[str, Any],
    expected_team_id: str,
    expected_entitlements: dict[str, Any],
) -> None:
    verify_signed_code(
        app_path,
        description="Signed application",
        expected_identifier=profile["bundle_identifier"],
        expected_team_id=expected_team_id,
        expected_entitlements=expected_entitlements,
        deep=True,
    )


def verify_signed_nested(
    app_path: Path,
    profile: dict[str, Any],
    spec: dict[str, Any],
    expected_team_id: str,
) -> None:
    entitlement_path = safe_profile_path(spec["entitlements"])
    with entitlement_path.open("rb") as handle:
        expected_entitlements = plistlib.load(handle)
    verify_signed_code(
        app_path / spec["path"],
        description=f"Signed nested executable {spec['path']}",
        expected_identifier=spec["identifier"],
        expected_team_id=expected_team_id,
        expected_entitlements=expected_entitlements,
        deep=False,
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


def compare_signed_payload(signed_app: Path, candidate_app: Path, profile: dict[str, Any]) -> None:
    relative_paths = [f"Contents/MacOS/{profile['executable']}"]
    relative_paths += [spec["path"] for spec in nested_executables(profile)]
    for relative in relative_paths:
        reference = signed_app / relative
        candidate = candidate_app / relative
        if candidate.is_symlink() or not candidate.is_file():
            fail(f"Packaged artifact is missing signed code: {relative}")
        if sha256_file(reference) != sha256_file(candidate):
            fail(f"Packaged artifact contains different signed code: {relative}")


def create_and_verify_zip(
    app_path: Path,
    output: Path,
    profile: dict[str, Any],
) -> None:
    run(["ditto", "-c", "-k", "--norsrc", "--keepParent", str(app_path), str(output)])
    with tempfile.TemporaryDirectory(prefix="broker-verify-zip-") as temporary:
        extracted = Path(temporary)
        run(["ditto", "-x", "-k", str(output), str(extracted)])
        candidate = extracted / profile["bundle_name"]
        compare_signed_payload(app_path, candidate, profile)
        run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(candidate)])
        run(["xcrun", "stapler", "validate", str(candidate)])


def stage_volume_icon(app_path: Path, staging: Path) -> bool:
    """Copy the application's icon into the disk image so Finder shows it on the volume.

    The icon is read from the bundle that already passed preflight, and it is checked again here:
    only a real `.icns` is accepted, never a Mach-O and never a symlink. The disk image is a signed
    artifact, so nothing enters it that has not been looked at.

    Returns whether an icon was staged; a bundle without one is not an error.
    """
    resources = app_path / "Contents" / "Resources"
    candidates = sorted(resources.glob("*.icns")) if resources.is_dir() else []
    if not candidates:
        print("No application icon found; the disk image keeps the default volume icon.")
        return False

    icon = candidates[0]
    if icon.is_symlink() or not icon.is_file():
        fail(f"Application icon is not a regular file: {icon.name}")
    if is_macho(icon):
        fail(f"Application icon is Mach-O code, not an icon: {icon.name}")
    with icon.open("rb") as handle:
        if handle.read(4) != b"icns":
            fail(f"Application icon is not an icns file: {icon.name}")

    shutil.copy2(icon, staging / ".VolumeIcon.icns")
    print(f"Disk image volume icon: {icon.name}")
    return True


def create_and_verify_dmg(
    app_path: Path,
    output: Path,
    profile: dict[str, Any],
    identity: str,
    apple_id: str,
    team_id: str,
    password: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="broker-dmg-") as temporary:
        temporary_path = Path(temporary)
        staging = temporary_path / "staging"
        staging.mkdir()
        run(["ditto", str(app_path), str(staging / profile["bundle_name"])])
        os.symlink("/Applications", staging / "Applications")
        volume_icon = stage_volume_icon(app_path, staging)

        # A volume icon can only be marked on a mounted, writable image, so the disk image is
        # built read-write, marked, and then converted to the compressed image that ships. The
        # custom-icon attribute survives that conversion.
        writable = temporary_path / "writable.dmg"
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
                "UDRW" if volume_icon else "UDZO",
                str(writable if volume_icon else output),
            ]
        )
        if volume_icon:
            mount_point = Path("/Volumes") / profile["dmg_volume_name"]
            run(["hdiutil", "attach", str(writable), "-nobrowse", "-noverify"])
            try:
                run(["xcrun", "SetFile", "-a", "C", str(mount_point)])
            finally:
                run(["hdiutil", "detach", str(mount_point), "-quiet"], check=False)
            run(["hdiutil", "convert", str(writable), "-format", "UDZO", "-o", str(output), "-ov"])
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
            compare_signed_payload(app_path, candidate, profile)
            run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(candidate)])
            run(["xcrun", "stapler", "validate", str(candidate)])
        finally:
            if attached:
                run(["hdiutil", "detach", str(mount_point), "-quiet"], check=False)


def verify_preflight_manifest(
    manifest_path: Path,
    app: str,
    version: str,
    pre_sign: dict[str, Any],
    expected_profile_digest: str,
) -> None:
    """Re-verify every digest the secretless preflight recorded, before any secret is used."""
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("Preflight manifest is missing.")
    try:
        with manifest_path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception as error:
        fail(f"Preflight manifest is not valid JSON: {error}")
    if not isinstance(manifest, dict):
        fail("Preflight manifest must be an object.")
    if manifest.get("profile") != app or manifest.get("version") != version:
        fail("Preflight manifest describes a different profile or version.")
    if manifest.get("profile_digest") != expected_profile_digest:
        fail("Preflight manifest was produced against a different broker profile.")

    application = manifest.get("application")
    if not isinstance(application, dict):
        fail("Preflight manifest does not describe an application.")
    for key in ("tree_sha256", "main_executable_sha256"):
        if application.get(key) != pre_sign[key]:
            fail(f"Preflight manifest {key} does not match the revalidated bundle.")

    entries = application.get("nested_executables", [])
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        fail("Preflight manifest nested executable records are malformed.")
    recorded = {entry.get("path"): entry.get("sha256") for entry in entries}
    current = {entry["path"]: entry["sha256"] for entry in pre_sign["nested_executables"]}
    if recorded != current:
        fail("Preflight manifest nested executable digests do not match the revalidated bundle.")


def read_provisioning_profile(app: str, profile: dict[str, Any]) -> bytes:
    """Read the app's provisioning profile from the broker repository.

    A provisioning profile is not a secret: a copy of it ships inside every
    downloaded app. Keeping it in the repository rather than in the signing
    environment means it is reviewable, diffable, and replaceable by a pull
    request instead of by an unlogged secret update.
    """
    path = safe_profile_path(profile["provisioning_profile"]["path"])
    if not path.is_file():
        fail(f"Profile {app} declares a provisioning profile that is missing: {path.name}")
    return path.read_bytes()


def signing_certificate_hashes(keychain: Path) -> set[str]:
    """The SHA-1 fingerprints security reports for the imported identities."""
    result = run(
        ["security", "find-identity", "-v", "-p", "codesigning", str(keychain)],
        capture=True,
    )
    return {match.upper() for match in re.findall(r"\b([0-9A-Fa-f]{40})\b", result.stdout)}


def embed_provisioning_profile(
    app: str,
    app_path: Path,
    profile: dict[str, Any],
    team_id: str,
    expected_entitlements: dict[str, Any],
    keychain: Path,
    work: Path,
) -> dict[str, Any] | None:
    """Place the app's provisioning profile in the bundle, after checking it fits.

    Everything here is checked before the profile is written, because a profile
    that does not match is worse than none: the app is signed, notarized and
    published, and still refuses to launch. The checks are deliberately kept
    independent of how the profile was obtained, so a mistake in the issuing
    code cannot ship a bundle that will not run.
    """
    declared = profile.get("provisioning_profile")
    if declared is None:
        return None

    payload = read_provisioning_profile(app, profile)

    source = work / "embedded.provisionprofile"
    source.write_bytes(payload)
    source.chmod(0o600)
    # A profile is a CMS envelope; the plist inside it is what macOS reads. It is
    # decoded to a file rather than to stdout because a binary plist would not
    # survive being captured as text.
    decoded_path = work / "provisionprofile.plist"
    run(
        ["security", "cms", "-D", "-i", str(source), "-o", str(decoded_path)],
        display=False,
    )
    try:
        with decoded_path.open("rb") as handle:
            contents = plistlib.load(handle)
    except (plistlib.InvalidFileException, ValueError) as error:
        fail(f"The stored file is not a provisioning profile: {error}")
    if not isinstance(contents, dict):
        fail("The stored file is not a provisioning profile.")

    if team_id not in contents.get("TeamIdentifier", []):
        fail(f"Provisioning profile belongs to another team than {team_id}.")
    expiration = contents.get("ExpirationDate")
    if not isinstance(expiration, datetime.datetime):
        fail("Provisioning profile has no expiration date.")
    # plistlib returns naive UTC for plist dates.
    if expiration.replace(tzinfo=datetime.timezone.utc) <= datetime.datetime.now(
        datetime.timezone.utc
    ):
        fail(f"Provisioning profile expired on {expiration.date().isoformat()}.")
    # A development profile lists the Macs it was issued for and works nowhere
    # else. Distributing one produces a release that launches on the maintainer's
    # machine and on no other, which is indistinguishable from a working release
    # until somebody else downloads it.
    if not contents.get("ProvisionsAllDevices"):
        fail(
            "Provisioning profile is limited to registered devices; Developer ID "
            "distribution needs a profile that provisions all devices."
        )

    granted = contents.get("Entitlements")
    if not isinstance(granted, dict):
        fail("Provisioning profile grants no entitlements.")
    ungranted = [
        entitlement
        for entitlement in restricted_entitlements(expected_entitlements)
        if not granted.get(entitlement)
    ]
    if ungranted:
        fail(f"Provisioning profile does not grant: {', '.join(ungranted)}.")
    application_identifier = granted.get("com.apple.application-identifier")
    expected_identifier = f"{team_id}.{profile['bundle_identifier']}"
    if application_identifier not in (None, expected_identifier):
        fail(
            f"Provisioning profile is for {application_identifier}, not {expected_identifier}."
        )

    # A profile only authorises the certificates it names. Signing with one it
    # does not list produces the same silent launch failure as shipping no
    # profile at all, so the two are matched here rather than on a user's Mac.
    certificates = contents.get("DeveloperCertificates")
    if not isinstance(certificates, list) or not certificates:
        fail("Provisioning profile names no signing certificates.")
    fingerprints = {
        hashlib.sha1(bytes(entry), usedforsecurity=False).hexdigest().upper()
        for entry in certificates
        if isinstance(entry, bytes)
    }
    if not fingerprints & signing_certificate_hashes(keychain):
        fail("Provisioning profile does not cover the signing certificate.")

    destination = app_path / PROVISIONING_PROFILE_PATH
    if destination.exists() or destination.is_symlink():
        fail("Application bundle already contains a provisioning profile.")
    shutil.copyfile(source, destination)
    destination.chmod(0o644)
    return {
        "name": contents.get("Name"),
        "uuid": contents.get("UUID"),
        "expires": expiration.date().isoformat(),
        "sha256": sha256_file(destination),
        "path": declared["path"],
    }


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
    preflight_manifest = Path(args.preflight_manifest).resolve()
    verify_preflight_manifest(preflight_manifest, args.app, version, pre_sign, args.profile_digest)

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
    declared_team_id = profile.get("team_id")
    if declared_team_id is not None and declared_team_id != team_id:
        fail("Profile team_id does not match APPLE_TEAM_ID; the build and signing identities differ.")

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
            # Written before anything is signed so the app signature seals it.
            provisioning = embed_provisioning_profile(
                args.app,
                app_path,
                profile,
                team_id,
                expected_entitlements,
                keychain_path,
                temporary_path,
            )
            specs = nested_executables(profile)
            for spec in specs:
                run(
                    [
                        "codesign",
                        "--force",
                        "--sign",
                        identity,
                        "--identifier",
                        spec["identifier"],
                        "--options",
                        "runtime",
                        "--timestamp",
                        "--entitlements",
                        str(safe_profile_path(spec["entitlements"])),
                        str(app_path / spec["path"]),
                    ]
                )
                verify_signed_nested(app_path, profile, spec, team_id)
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
            for spec in specs:
                verify_signed_nested(app_path, profile, spec, team_id)

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
            for spec in specs:
                verify_signed_nested(app_path, profile, spec, team_id)
            run(["spctl", "--assess", "--type", "execute", "--verbose=4", str(app_path)])
            if provisioning is not None:
                # Stapling rewrites the bundle, so confirm the profile is still
                # the one that was checked. Without it the app cannot launch.
                embedded = app_path / PROVISIONING_PROFILE_PATH
                if embedded.is_symlink() or not embedded.is_file():
                    fail("Signed application lost its provisioning profile.")
                if sha256_file(embedded) != provisioning["sha256"]:
                    fail("Signed application carries a different provisioning profile.")

            reference_executable = app_path / "Contents" / "MacOS" / profile["executable"]
            artifacts: list[dict[str, Any]] = []
            for artifact in profile["artifacts"]:
                name = artifact["name"].format(version=version)
                destination = output_dir / name
                if artifact["type"] == "zip":
                    create_and_verify_zip(app_path, destination, profile)
                else:
                    create_and_verify_dmg(
                        app_path,
                        destination,
                        profile,
                        identity,
                        apple_id,
                        team_id,
                        apple_password,
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
                    "provisioning_profile": provisioning,
                    "main_executable_sha256": sha256_file(reference_executable),
                    "nested_executables": [
                        {
                            "path": spec["path"],
                            "identifier": spec["identifier"],
                            "sha256": sha256_file(app_path / spec["path"]),
                        }
                        for spec in specs
                    ],
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
