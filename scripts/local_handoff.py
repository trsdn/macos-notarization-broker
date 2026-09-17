#!/usr/bin/env python3
"""Encrypted owner-attested local release handoff. Never executes submitted code."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

import age_tool
import broker

REPOSITORY = "trsdn/macos-notarization-broker"
REPOSITORY_ID = 1315404585
OWNER_ID = 24534196
WORKFLOW = "notarize-local.yml"
CONFIG = broker.PROFILE_ROOT / "local-handoff.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RECIPIENT = re.compile(r"^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$")
REQUEST_ID = re.compile(r"^local-[0-9a-f]{32}$")
MAX_TRANSFER = 1024 * 1024 * 1024
INPUT_KEYS = {
    "app", "tag", "source_sha", "source_ref_sha", "source_tag_object_sha",
    "archive_sha256", "return_recipient", "request_id",
}


def check(condition: bool) -> None:
    if not condition:
        raise ValueError("Local handoff policy check failed")


def private_directory(path: Path) -> Path:
    check(not path.is_symlink())
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def write_json(path: Path, data: dict) -> None:
    check(not path.is_symlink())
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


def read_json(path: Path) -> dict:
    check(not path.is_symlink() and path.stat().st_size < 1024 * 1024)
    value = json.loads(path.read_text())
    check(isinstance(value, dict))
    return value


def invoke(command: list[str], *, env: dict | None = None, binary: bool = False) -> str | bytes:
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    check(result.returncode == 0)
    return result.stdout if binary else result.stdout.decode().strip()


def api(path: str) -> dict | list:
    check(path.startswith(f"repos/{REPOSITORY}/") or path == f"repos/{REPOSITORY}" or path == "user")
    return json.loads(invoke(["gh", "api", path]))


def config() -> dict:
    value = read_json(CONFIG)
    check(set(value) == {"schema_version", "profiles", "staging_release", "signing_recipient"})
    check(value.get("schema_version") == 1)
    check(value.get("profiles") == ["subvocal", "subvocal-light"])
    check(value.get("staging_release") == "local-handoffs")
    check(RECIPIENT.fullmatch(value.get("signing_recipient", "")) is not None)
    return value


def validate_inputs(inputs: dict) -> dict:
    check(set(inputs) == INPUT_KEYS and all(isinstance(v, str) for v in inputs.values()))
    check(inputs["app"] in config()["profiles"])
    broker.validate_tag(inputs["tag"])
    for key in ("source_sha", "source_ref_sha"):
        check(broker.FULL_SHA_PATTERN.fullmatch(inputs[key]) is not None)
    tag_object = inputs["source_tag_object_sha"]
    check(not tag_object or broker.FULL_SHA_PATTERN.fullmatch(tag_object) is not None)
    check((tag_object == inputs["source_ref_sha"]) if tag_object else inputs["source_ref_sha"] == inputs["source_sha"])
    check(SHA256.fullmatch(inputs["archive_sha256"]) is not None)
    check(RECIPIENT.fullmatch(inputs["return_recipient"]) is not None)
    check(REQUEST_ID.fullmatch(inputs["request_id"]) is not None)
    return inputs


def runner_request() -> dict:
    check(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY)
    check(os.environ.get("GITHUB_REPOSITORY_ID") == str(REPOSITORY_ID))
    check(os.environ.get("GITHUB_ACTOR_ID") == str(OWNER_ID))
    check(os.environ.get("GITHUB_REF") == "refs/heads/main")
    check(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
    inputs = validate_inputs({key: os.environ.get(f"INPUT_{key.upper()}", "") for key in INPUT_KEYS})
    run_id = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    commit = os.environ["GITHUB_SHA"]
    check(run_id.isdigit() and int(run_id) > 0 and attempt == "1")
    check(broker.FULL_SHA_PATTERN.fullmatch(commit) is not None)
    return {
        "schema_version": 1,
        "inputs": inputs,
        "run_id": run_id,
        "run_attempt": attempt,
        "broker_commit": commit,
        "profile_digest": broker.profile_digest(inputs["app"], broker.get_profile(inputs["app"])),
        "handoff_policy_digest": broker.sha256_file(CONFIG),
        "source_verification": "owner-attested-local-build",
    }


def age_encrypt(age: Path, recipient: str, source: Path, target: Path) -> None:
    check(RECIPIENT.fullmatch(recipient) is not None and not target.exists())
    invoke([str(age), "--encrypt", "--recipient", recipient, "--output", str(target), str(source)])


def age_decrypt(age: Path, identity: Path, source: Path, target: Path) -> None:
    check(not target.exists() and source.stat().st_size <= MAX_TRANSFER)
    invoke([str(age), "--decrypt", "--identity", str(identity), "--output", str(target), str(source)])


def generate_identity(age: Path, path: Path) -> str:
    check(not path.exists())
    invoke([str(age.parent / "age-keygen"), "--output", str(path)])
    path.chmod(0o600)
    recipient = invoke([str(age.parent / "age-keygen"), "-y", str(path)])
    check(isinstance(recipient, str) and RECIPIENT.fullmatch(recipient) is not None)
    return recipient


def pack_files(destination: Path, files: dict[str, Path]) -> None:
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, path in files.items():
            check(Path(name).name == name and not path.is_symlink() and path.is_file())
            archive.write(path, name)


def unpack_files(source: Path, destination: Path, expected: set[str]) -> None:
    private_directory(destination)
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        check(len(entries) == len(expected) and {e.filename for e in entries} == expected)
        check(sum(e.file_size for e in entries) <= MAX_TRANSFER)
        for entry in entries:
            mode = entry.external_attr >> 16
            check(Path(entry.filename).name == entry.filename and not entry.is_dir())
            check(not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in {0, stat.S_IFREG})
            path = destination / entry.filename
            check(not path.exists())
            with archive.open(entry) as incoming, path.open("xb") as output:
                shutil.copyfileobj(incoming, output)
            path.chmod(0o600)


def validate_archive(request: dict, archive: Path, work: Path, *, tree: str | None = None,
                     digest: str | None = None, repack: bool = False) -> dict:
    inputs = request["inputs"]
    manifest = work / "preflight-manifest.json"
    broker.command_validate(argparse.Namespace(
        app=inputs["app"], version=inputs["tag"][1:], archive=str(archive),
        extract_to=str(work / "app"), expected_archive_sha=digest,
        expected_tree_sha=tree, validated_archive=str(work / "validated-app.zip") if repack else None,
        manifest=str(manifest),
    ))
    return read_json(manifest)


def start(work: Path, age: Path) -> None:
    request = runner_request()
    write_json(work / "request.json", request)
    recipient = generate_identity(age, work / "preflight.identity")
    public = private_directory(work / "public")
    write_json(public / "challenge.json", {
        "request": request, "recipient": recipient,
        "signing_recipient": config()["signing_recipient"],
    })


def input_asset_name(request: dict) -> str:
    return f"{request['inputs']['request_id']}-{request['run_id']}-{request['run_attempt']}.age"


def release_assets(release_id: int) -> list[dict]:
    assets = json.loads(invoke([
        "gh", "api", f"repos/{REPOSITORY}/releases/{release_id}/assets?per_page=100",
    ]))
    check(isinstance(assets, list))
    return assets


def download_asset(asset: dict, target: Path) -> None:
    check(type(asset.get("id")) is int and 0 < asset.get("size", 0) <= MAX_TRANSFER)
    check(asset.get("uploader", {}).get("id") == OWNER_ID)
    check(asset.get("state") == "uploaded")
    with target.open("xb") as output:
        result = subprocess.run([
            "gh", "api", f"repos/{REPOSITORY}/releases/assets/{asset['id']}",
            "-H", "Accept: application/octet-stream",
        ], stdout=output, stderr=subprocess.PIPE)
    check(result.returncode == 0 and target.stat().st_size == asset["size"])
    digest = asset.get("digest")
    check(isinstance(digest, str) and digest == "sha256:" + broker.sha256_file(target))


def preflight(work: Path, age: Path) -> None:
    request = read_json(work / "request.json")
    check(request == runner_request())
    release = api(f"repos/{REPOSITORY}/releases/tags/{config()['staging_release']}")
    check(isinstance(release, dict) and release["author"]["id"] == OWNER_ID)
    asset = None
    for _ in range(120):
        matches = [a for a in release_assets(release["id"]) if a["name"] == input_asset_name(request)]
        check(len(matches) <= 1)
        if matches:
            asset = matches[0]
            break
        time.sleep(5)
    check(asset is not None)
    encrypted = work / "submitted.age"
    download_asset(asset, encrypted)
    unsigned = work / "unsigned-app.zip"
    age_decrypt(age, work / "preflight.identity", encrypted, unsigned)
    (work / "preflight.identity").unlink()
    check(broker.sha256_file(unsigned) == request["inputs"]["archive_sha256"])
    manifest = validate_archive(request, unsigned, work, digest=request["inputs"]["archive_sha256"], repack=True)
    binding = {
        "request": request, "input_asset_id": asset["id"],
        "input_ciphertext_sha256": broker.sha256_file(encrypted),
        "validated_archive_sha256": broker.sha256_file(work / "validated-app.zip"),
        "tree_sha256": manifest["application"]["tree_sha256"],
    }
    write_json(work / "binding.json", binding)
    transport = work / "validated-transfer.zip"
    pack_files(transport, {name: work / name for name in (
        "validated-app.zip", "preflight-manifest.json", "binding.json",
    )})
    destination = private_directory(work / "outbound") / "validated.age"
    age_encrypt(age, config()["signing_recipient"], transport, destination)
    broker.append_github_outputs({
        "ciphertext_sha256": broker.sha256_file(destination),
        "tree_sha256": binding["tree_sha256"],
    })


def sign_prepare(work: Path, age: Path) -> None:
    request = runner_request()
    ciphertext = Path("encrypted-input/validated.age")
    expected = os.environ.get("EXPECTED_CIPHERTEXT_SHA256", "")
    check(SHA256.fullmatch(expected) is not None and broker.sha256_file(ciphertext) == expected)
    identity = work / "signing.identity"
    key = os.environ.pop("LOCAL_HANDOFF_AGE_IDENTITY")
    check("AGE-SECRET-KEY-" in key)
    identity.write_text(key)
    identity.chmod(0o600)
    check(invoke([str(age.parent / "age-keygen"), "-y", str(identity)]) == config()["signing_recipient"])
    transfer = work / "validated-transfer.zip"
    try:
        age_decrypt(age, identity, ciphertext, transfer)
    finally:
        identity.unlink(missing_ok=True)
    unpack_files(transfer, work / "received", {
        "validated-app.zip", "preflight-manifest.json", "binding.json",
    })
    binding = read_json(work / "received/binding.json")
    check(binding.get("request") == request)
    check(binding["tree_sha256"] == os.environ.get("EXPECTED_TREE_SHA256"))
    manifest = validate_archive(
        request, work / "received/validated-app.zip", work,
        tree=binding["tree_sha256"], digest=binding["validated_archive_sha256"],
    )
    broker.verify_preflight_manifest(
        work / "received/preflight-manifest.json", request["inputs"]["app"],
        request["inputs"]["tag"][1:], manifest["application"], request["profile_digest"],
    )
    write_json(work / "verified.json", binding)


def sign_finish(work: Path, age: Path) -> None:
    binding = read_json(work / "verified.json")
    request = binding["request"]
    check(request == runner_request())
    inputs = request["inputs"]
    profile = broker.get_profile(inputs["app"])
    output = work / "signed"
    broker.command_sign(argparse.Namespace(
        app=inputs["app"], version=inputs["tag"][1:], app_root=str(work / "app"),
        expected_tree_sha=binding["tree_sha256"], profile_digest=request["profile_digest"],
        preflight_manifest=str(work / "received/preflight-manifest.json"), output_dir=str(output),
        request_id=inputs["request_id"], source_repository=profile["repository"],
        source_repository_id=profile["repository_id"], source_tag=inputs["tag"],
        source_ref_sha=inputs["source_ref_sha"], source_tag_object_sha=inputs["source_tag_object_sha"],
        source_commit_sha=inputs["source_sha"], broker_repository=REPOSITORY,
        broker_commit_sha=request["broker_commit"], run_id=request["run_id"], run_attempt=request["run_attempt"],
    ))
    provenance_path = output / "provenance.json"
    provenance = read_json(provenance_path)
    provenance["source"]["verification"] = "owner-attested-local-build"
    provenance["local_handoff"] = binding
    write_json(provenance_path, provenance)
    transfer = work / "result.zip"
    pack_files(transfer, {p.name: p for p in output.iterdir()})
    destination = private_directory(work / "outbound") / "result.age"
    age_encrypt(age, inputs["return_recipient"], transfer, destination)


@contextlib.contextmanager
def silence_private_diagnostics():
    """Capture subprocess and Python output at the fd boundary, never in public logs."""
    sys.stdout.flush()
    sys.stderr.flush()
    saved = (os.dup(1), os.dup(2))
    sink = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(sink, 1)
        os.dup2(sink, 2)
        yield
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for descriptor in (*saved, sink):
            os.close(descriptor)


def remote(command: str) -> int:
    try:
        with silence_private_diagnostics():
            os.umask(0o077)
            work = private_directory(Path(".local-handoff").resolve())
            os.environ["TMPDIR"] = str(private_directory(work / "temp"))
            age = age_tool.install(work / "age")
            {"start": start, "preflight": preflight, "sign-prepare": sign_prepare,
             "sign-finish": sign_finish}[command](work, age)
    except Exception:
        print("Encrypted local handoff failed; no private diagnostics were published.", file=sys.stderr)
        return 1
    print("Encrypted local handoff step completed.")
    return 0


def source_attestation(source: Path, app: str, tag: str) -> dict:
    profile = broker.get_profile(app)
    check(not invoke(["git", "-C", str(source), "status", "--porcelain"]))
    local_sha = invoke(["git", "-C", str(source), "rev-parse", "HEAD"])
    check(invoke(["git", "-C", str(source), "rev-parse", f"{tag}^{{commit}}"]) == local_sha)
    lock = read_json(source / "Subvocal/Package.resolved")
    check(lock == read_json(broker.safe_profile_path(profile["dependency_lock"])))
    repository = profile["repository"]
    document = json.loads(invoke(["gh", "api", f"repos/{repository}"]))
    check(document["id"] == profile["repository_id"] and document["full_name"].lower() == repository.lower())
    ref = json.loads(invoke(["gh", "api", f"repos/{repository}/git/ref/tags/{tag}"]))["object"]
    ref_sha = ref["sha"]
    tag_sha = ref_sha if ref["type"] == "tag" else ""
    seen = set()
    for _ in range(8):
        check(broker.FULL_SHA_PATTERN.fullmatch(ref["sha"]) is not None and ref["sha"] not in seen)
        seen.add(ref["sha"])
        if ref["type"] == "commit":
            check(ref["sha"] == local_sha)
            return {"source_sha": local_sha, "source_ref_sha": ref_sha, "source_tag_object_sha": tag_sha}
        check(ref["type"] == "tag")
        ref = json.loads(invoke(["gh", "api", f"repos/{repository}/git/tags/{ref['sha']}"]))["object"]
    raise ValueError("Source tag resolution failed")


def verify_run(run: dict, state: dict) -> None:
    check(run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main")
    check(run.get("head_sha") == state["broker_commit"] and run.get("run_attempt") == 1)
    check(run.get("actor", {}).get("id") == OWNER_ID)
    check(run.get("repository", {}).get("id") == REPOSITORY_ID)
    check(run.get("path") == f".github/workflows/{WORKFLOW}")


def download_run_artifact(run_id: str, name: str, destination: Path) -> None:
    document = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100")
    matches = [a for a in document["artifacts"] if a["name"] == name and not a["expired"]]
    check(len(matches) == 1)
    artifact = matches[0]
    check(0 < artifact["size_in_bytes"] <= MAX_TRANSFER)
    data = invoke(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"], binary=True)
    check(len(data) <= MAX_TRANSFER)
    destination.write_bytes(data)


def local_request(args: argparse.Namespace) -> None:
    check(args.app is not None and args.tag is not None and args.source and args.app_bundle)
    cfg = config()
    check(args.app in cfg["profiles"])
    broker.validate_tag(args.tag)
    check(api("user")["id"] == OWNER_ID)
    check(api(f"repos/{REPOSITORY}")["id"] == REPOSITORY_ID)
    source = Path(args.source).resolve()
    attestation = source_attestation(source, args.app, args.tag)
    request_id = "local-" + uuid.uuid4().hex
    work = private_directory(Path(args.output).resolve() / request_id)
    age = age_tool.install(work / "age")
    recipient = generate_identity(age, work / "return.identity")
    app = Path(args.app_bundle).resolve()
    profile = broker.get_profile(args.app)
    check(app.name == profile["bundle_name"])
    broker.validate_app_tree(app, profile, args.tag[1:], require_unsigned=True)
    staged_app = work / "staged" / profile["bundle_name"]
    shutil.copytree(app, staged_app, symlinks=True)
    broker.make_resource_bundles_writable(staged_app, profile)
    broker.validate_app_tree(staged_app, profile, args.tag[1:], require_unsigned=True)
    unsigned = work / "unsigned-app.zip"
    invoke(["ditto", "-c", "-k", "--norsrc", "--keepParent", str(staged_app), str(unsigned)])
    check(unsigned.stat().st_size <= profile["max_archive_bytes"])
    inputs = validate_inputs({
        "app": args.app, "tag": args.tag, **attestation,
        "archive_sha256": broker.sha256_file(unsigned), "return_recipient": recipient, "request_id": request_id,
    })
    broker_commit = api(f"repos/{REPOSITORY}/git/ref/heads/main")["object"]["sha"]
    # The local helper and its reviewed policy must be the same revision that runs remotely.
    check(invoke(["git", "-C", str(broker.ROOT), "rev-parse", "HEAD"]) == broker_commit)
    check(not invoke(["git", "-C", str(broker.ROOT), "status", "--porcelain", "--untracked-files=no"]))
    try:
        release = api(f"repos/{REPOSITORY}/releases/tags/{cfg['staging_release']}")
    except ValueError:
        invoke(["gh", "release", "create", cfg["staging_release"], "--repo", REPOSITORY,
                "--target", broker_commit, "--title", "Encrypted local handoffs",
                "--notes", "Opaque encrypted staging files only. Not application releases.", "--prerelease"])
        release = api(f"repos/{REPOSITORY}/releases/tags/{cfg['staging_release']}")
    check(release["author"]["id"] == OWNER_ID)
    state = {"inputs": inputs, "source": str(source), "broker_commit": broker_commit}
    write_json(work / "state.json", state)
    command = ["gh", "workflow", "run", WORKFLOW, "--repo", REPOSITORY, "--ref", "main"]
    for key, value in inputs.items():
        command += ["--field", f"{key}={value}"]
    invoke(command)
    title = f"Local notarize {args.app} {args.tag} ({request_id})"
    run_id = None
    for _ in range(60):
        runs = api(f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW}/runs?event=workflow_dispatch&per_page=100")
        matches = [r for r in runs["workflow_runs"] if r.get("display_title") == title]
        check(len(matches) <= 1)
        if matches:
            verify_run(matches[0], state)
            run_id = str(matches[0]["id"])
            break
        time.sleep(3)
    check(run_id is not None)
    state["run_id"] = run_id
    write_json(work / "state.json", state)
    challenge_archive = work / "challenge.zip"
    for _ in range(120):
        run = api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
        verify_run(run, state)
        check(run.get("status") != "completed")
        artifacts = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100")
        if any(a["name"] == f"local-challenge-{request_id}" for a in artifacts["artifacts"]):
            download_run_artifact(run_id, f"local-challenge-{request_id}", challenge_archive)
            break
        time.sleep(5)
    check(challenge_archive.exists())
    unpack_files(challenge_archive, work / "challenge", {"challenge.json"})
    challenge = read_json(work / "challenge/challenge.json")
    request = challenge["request"]
    check(request["inputs"] == inputs and request["run_id"] == run_id and request["run_attempt"] == "1")
    check(request["broker_commit"] == broker_commit and request["handoff_policy_digest"] == broker.sha256_file(CONFIG))
    check(request["profile_digest"] == broker.profile_digest(args.app, profile))
    check(challenge["signing_recipient"] == cfg["signing_recipient"])
    check(source_attestation(source, args.app, args.tag) == attestation)
    encrypted = work / input_asset_name(request)
    age_encrypt(age, challenge["recipient"], unsigned, encrypted)
    invoke(["gh", "release", "upload", cfg["staging_release"], str(encrypted), "--repo", REPOSITORY])
    unsigned.unlink()
    print(f"Ciphertext submitted to run {run_id}. Review and approve macos-signing separately.")
    print(f"After completion: scripts/request-local.sh --resume {work / 'state.json'}")


def local_receive(path: Path) -> None:
    state = read_json(path)
    inputs = validate_inputs(state["inputs"])
    attestation = source_attestation(Path(state["source"]), inputs["app"], inputs["tag"])
    check(all(inputs[k] == v for k, v in attestation.items()))
    run = api(f"repos/{REPOSITORY}/actions/runs/{state['run_id']}")
    verify_run(run, state)
    check(run["status"] == "completed" and run["conclusion"] == "success")
    work = path.resolve().parent
    age = age_tool.install(work / "age")
    check(not (work / "result").exists())
    attempt = private_directory(work / ("receive-" + uuid.uuid4().hex))
    outer = attempt / "download.zip"
    download_run_artifact(state["run_id"], f"local-result-{inputs['request_id']}", outer)
    unpack_files(outer, attempt / "download", {"result.age"})
    result_zip = attempt / "result.zip"
    age_decrypt(age, work / "return.identity", attempt / "download/result.age", result_zip)
    profile = broker.get_profile(inputs["app"])
    names = {a["name"].format(version=inputs["tag"][1:]) for a in profile["artifacts"]}
    result = attempt / "result"
    unpack_files(result_zip, result, names | {n + ".sha256" for n in names} | {
        "provenance.json", "preflight-manifest.json",
    })
    provenance = read_json(result / "provenance.json")
    check(provenance["profile"] == inputs["app"] and provenance["request_id"] == inputs["request_id"])
    check(provenance["local_handoff"]["request"]["inputs"] == inputs)
    check(provenance["broker"]["commit_sha"] == state["broker_commit"])
    check(str(provenance["broker"]["run_id"]) == state["run_id"])
    check(provenance["source"]["verification"] == "owner-attested-local-build")
    check(provenance["source"]["repository"] == profile["repository"])
    check(provenance["source"]["repository_id"] == profile["repository_id"])
    check(provenance["source"]["tag"] == inputs["tag"])
    check(provenance["source"]["commit_sha"] == inputs["source_sha"])
    check(provenance["source"]["ref_target_sha"] == inputs["source_ref_sha"])
    check(provenance["source"]["tag_object_sha"] == (inputs["source_tag_object_sha"] or None))
    check(provenance["profile_digest"] == broker.profile_digest(inputs["app"], profile))
    check({a["name"] for a in provenance["artifacts"]} == names)
    for artifact in provenance["artifacts"]:
        check(broker.sha256_file(result / artifact["name"]) == artifact["sha256"])
    result.rename(work / "result")
    shutil.rmtree(attempt)
    (work / "return.identity").unlink()
    print(f"Verified notarized artifacts: {work / 'result'}")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] in {"start", "preflight", "sign-prepare", "sign-finish"}:
        return remote(sys.argv[1])
    parser = argparse.ArgumentParser()
    parser.add_argument("app", nargs="?")
    parser.add_argument("tag", nargs="?")
    parser.add_argument("--source")
    parser.add_argument("--app-bundle")
    parser.add_argument("--output", default=str(broker.ROOT / ".local-handoff-requests"))
    parser.add_argument("--resume", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.resume:
            local_receive(args.resume)
        else:
            local_request(args)
    except Exception as error:
        print(f"Local handoff failed: {error}. No plaintext was uploaded; "
              "no approval was bypassed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
