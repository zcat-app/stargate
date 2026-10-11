#!/usr/bin/env python3
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""Finite release preparation, promotion and offline installation boundaries.

Policy and executable selection belong to source C. Evidence E and release
directories are data. See docs/releasing.md and THREAT-MODEL.md §3.5.
"""
import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import urllib.parse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "target/release-tools"
REPOSITORY = "zcat-app/stargate"
API = "https://api.github.com/repos/" + REPOSITORY
SERVICES = {"stargate-dp": "stargate-dp", "stargate-control": "stargate-control",
            "tor": "stargate-tor", "tor-observer": "stargate-tor-observer"}
MAX_JSON = 8 * 1024 * 1024
MAX_ARCHIVE = 8 * 1024**3
MAX_UNPACKED = 16 * 1024**3
DISK_RESERVE = 1024**3
MAX_COMMAND_OUTPUT = 64 * 1024**2
MAX_PAYLOAD_BYTES = 512 * 1024**2


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def decode(data):
    require(len(data) <= MAX_JSON, "JSON exceeds bound")
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refusal("nonfinite JSON")))


def regular(path, limit=MAX_JSON):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), "expected regular file: " + str(path))
    require(path.stat().st_size <= limit, "file exceeds bound: " + str(path))
    return path.read_bytes()


def document(path):
    return decode(regular(path))


def fields(obj, expected, label):
    require(isinstance(obj, dict) and set(obj) == set(expected), label + " fields differ")


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256")
    return value


def commit(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "invalid commit")
    return value


def version(value):
    require(isinstance(value, str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", value), "invalid version")
    return value


def safe_path(value):
    require(isinstance(value, str) and value and "\\" not in value and "\x00" not in value,
            "invalid relative path")
    p = PurePosixPath(value)
    require(not p.is_absolute() and all(x not in ("", ".", "..") for x in value.split("/")),
            "unsafe relative path")
    return p


def write_json(path, obj):
    Path(path).write_bytes(canonical(obj))


def run(args, *, env=None, cwd=ROOT, log=None, timeout=600):
    """Bound local command output; overflow is failure, never a truncated PASS."""
    stdout, stderr = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    with (Path(log).open("wb") if log is not None else contextlib.nullcontext()) as record:
        process = subprocess.Popen(list(map(str, args)), cwd=cwd, env=env, start_new_session=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        completed = False
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, stdout)
                selector.register(process.stderr, selectors.EVENT_READ, stderr)
                while selector.get_map():
                    require(time.monotonic() < deadline, "command exceeded time bound: " + str(args[0]))
                    for key, _ in selector.select(min(1, max(0, deadline - time.monotonic()))):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        room = MAX_COMMAND_OUTPUT - len(stdout) - len(stderr)
                        if record is not None:
                            record.write(data[:room])
                        require(len(data) <= room, "command output exceeded bound: " + str(args[0]))
                        key.data.extend(data)
            process.wait(timeout=max(0.1, deadline - time.monotonic()))
            require(process.returncode == 0, "command failed: " + str(args[0]) + " " + str(args[1])
                    + "\n" + stderr.decode(errors="replace")[-4000:])
            completed = True
        finally:
            if not completed:
                # A child can inherit stdout after its parent exits. Kill this
                # command's private session even in that case on timeout.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
    return bytes(stdout)


def pins():
    p = document(ROOT / "scripts/release/inputs.json")
    fields(p, ("schema", "tools", "buildkit", "sbom_generator", "trust_selection", "signing_config", "extension"), "inputs")
    require(p["schema"] == 1, "unsupported inputs schema")
    return p


def tool(name):
    record = pins()["tools"][name]
    filename = "trusted-root.json" if name == "trusted-root" else name
    path = TOOLS / filename
    data = regular(path, 256 * 1024**2)
    expected = record["installed_sha256"]
    if expected is None:
        # An archive hash is the upstream assertion. Re-derive the member from
        # those verified bytes; a locally writable receipt is not authority.
        archive = regular(TOOLS / (name + ".download"), 256 * 1024**2)
        require(len(archive) == record["size"] and sha(archive) == record["sha256"], "tool archive changed")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
            entries = [m for m in tf.getmembers() if m.name == record["member"]]
            require(len(entries) == 1 and entries[0].isfile(), "invalid tool archive member")
            require(entries[0].size <= 256 * 1024**2, "tool member exceeds bound")
            expected = sha(tf.extractfile(entries[0]).read())
    require(sha(data) == digest(expected), "pinned tool changed: " + name)
    return path


def image_map(images):
    fields(images, SERVICES, "images")
    for service, repo in SERVICES.items():
        require(isinstance(images[service], str) and re.fullmatch(
            r"ghcr\.io/zcat-app/" + repo + r"@sha256:[0-9a-f]{64}", images[service]),
            "image is not the approved registry digest: " + service)
    return images


def compose(images):
    image_map(images)
    parser = tool("docker-compose")
    clean = {k: v for k, v in os.environ.items()
             if not k.startswith(("STARGATE_", "COMPOSE_", "DOCKER_"))}
    with tempfile.TemporaryDirectory(prefix="stargate-compose-") as directory:
        empty = Path(directory) / "empty.env"
        empty.touch()
        base = [parser, "-p", "stargate", "--env-file", empty, "-f"]
        flags = ["config", "--format", "json", "--no-interpolate", "--no-normalize",
                 "--no-path-resolution", "--no-env-resolution"]
        obj = decode(run([*base, ROOT / "compose/docker-compose.local.yml", *flags], env=clean))
        require(isinstance(obj, dict) and isinstance(obj.get("services"), dict), "invalid source Compose")
        fields(obj["services"], SERVICES, "Compose services")
        for name, service in obj["services"].items():
            for mount in service.get("volumes", []):
                if isinstance(mount, str):
                    source = mount.split(":", 1)[0]
                    require(not source.startswith((".", "~")), "relative bind is unsupported")
                elif isinstance(mount, dict) and mount.get("type") == "bind":
                    require(str(mount.get("source", "")).startswith("/"), "relative bind is unsupported")
            service["image"] = images[name]
            service.pop("build", None)
            if service.get("pull_policy") == "build":
                del service["pull_policy"]
        output = Path(directory) / "compose.json"
        write_json(output, obj)
        require(decode(run([*base, output, *flags], env=clean)) == obj, "Compose round trip differs")
    return obj


def source_identity(source, tag):
    commit(source)
    version(tag)
    require(run(["git", "rev-parse", "HEAD"]).decode().strip() == source, "HEAD is not source C")
    require(run(["git", "rev-parse", "--verify", "refs/tags/" + tag + "^{commit}"]).decode().strip() == source,
            "existing version tag is not source C")
    require(not run(["git", "status", "--porcelain", "--untracked-files=normal"]).strip(), "source checkout is dirty")
    require(not run(["git", "ls-files", "--others", "--exclude-standard", "scripts", "compose", ".github"]).strip(),
            "untracked source file")
    result = {}
    for row in run(["git", "ls-tree", "-rz", "--full-tree", source]).split(b"\0"):
        if not row:
            continue
        header, name = row.split(b"\t", 1)
        mode, kind, oid = header.decode().split()
        require(mode in ("100644", "100755") and kind == "blob", "source symlink/submodule is unsupported")
        relative = name.decode()
        safe_path(relative)
        require((ROOT / relative).resolve(strict=True) == ROOT / relative,
                "source path traverses a substituted symlink: " + relative)
        data = regular(ROOT / relative, MAX_ARCHIVE)
        actual_mode = "100755" if (ROOT / relative).stat().st_mode & 0o111 else "100644"
        require(actual_mode == mode, "source executable mode differs from C: " + relative)
        # Git's path clean filter authenticates checkout bytes against C.
        # Git archive exports CRLF for required CRLF paths, so the retained
        # manifest binds the delivered checkout/archive bytes (Principle IV).
        actual = run(["git", "hash-object", "--path=" + relative, "--", relative]).decode().strip()
        require(actual == oid, "source bytes differ from C: " + relative)
        result[relative] = {"sha256": sha(data), "mode": mode}
    require(result, "empty source manifest")
    return result


def verify_install(directory, output=None):
    directory = Path(directory).resolve(strict=True)
    manifest_path = directory / "release.json"
    manifest_data = regular(manifest_path)
    manifest = decode(manifest_data)
    fields(manifest, ("schema", "version", "source", "platform", "images", "compose_sha256",
                      "source_files", "artifacts", "pack_sha256"), "release manifest")
    require(manifest["schema"] == 1 and manifest["platform"] == "linux/amd64", "unsupported release")
    version(manifest["version"])
    commit(manifest["source"])
    digest(manifest["pack_sha256"])
    image_map(manifest["images"])
    expected_source = source_identity(manifest["source"], manifest["version"])
    require(manifest["source_files"] == expected_source, "release source-file identity differs")
    bundle = directory / "release.sigstore.json"
    bundle_data = regular(bundle)
    # The source-owned root and exact workflow identity are never taken from
    # the release document. Cosign supplies cryptographic/time/log validation.
    with tempfile.TemporaryDirectory(prefix="stargate-signature-") as temporary:
        snapshot = Path(temporary)
        (snapshot / "release.json").write_bytes(manifest_data)
        (snapshot / "bundle.json").write_bytes(bundle_data)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("COSIGN_", "SIGSTORE_"))}
        run([tool("cosign"), "verify-blob", "--bundle", snapshot / "bundle.json",
             *signature_flags(manifest["source"], manifest["version"]), snapshot / "release.json"], env=env)
    compose_path = directory / "compose.json"
    data = regular(compose_path)
    require(sha(data) == digest(manifest["compose_sha256"]), "release Compose hash differs")
    require(decode(data) == compose(manifest["images"]), "release Compose topology differs from source")
    if output is not None:
        # The installer uses these already-validated bytes from a private
        # directory, never reopens the untrusted input after verification.
        with Path(output).open("xb") as stream:
            stream.write(data)
        return Path(output).resolve()
    return compose_path


def inventory(directory):
    result = {}
    for path in sorted(Path(directory).rglob("*")):
        require(not path.is_symlink(), "symlink in data directory")
        if path.is_dir():
            continue
        require(stat.S_ISREG(path.lstat().st_mode), "nonregular artifact")
        result[path.relative_to(directory).as_posix()] = {"sha256": file_hash(path), "size": path.stat().st_size}
    return result


def check_inventory(directory, expected, *, excluded=()):
    require(isinstance(expected, dict) and expected, "empty artifact inventory")
    for name, record in expected.items():
        safe_path(name)
        fields(record, ("sha256", "size"), "file record")
        digest(record["sha256"])
        require(type(record["size"]) is int and 0 <= record["size"] <= MAX_UNPACKED, "invalid file size")
    actual = inventory(directory)
    for name in excluded:
        actual.pop(name, None)
    require(actual == expected, "file inventory differs")


def check_evidence(candidate_path, directory):
    candidate_data = regular(candidate_path)
    candidate = decode(candidate_data)
    source, tag = commit(candidate["source"]), version(candidate["version"])
    directory = Path(directory)
    index = document(directory / "index.json")
    fields(index, ("schema", "source", "version", "candidate_sha256", "files"), "evidence index")
    require(index["schema"] == 1 and index["source"] == source and index["version"] == tag
            and index["candidate_sha256"] == sha(candidate_data), "evidence candidate is stale")
    require(len(index["files"]) <= 128 and sum(r["size"] for r in index["files"].values()) <= 64 * 1024**2,
            "evidence exceeds bound")
    check_inventory(directory, index["files"], excluded=("index.json",))

    def report_body(name):
        safe_path(name)
        require(name in index["files"] and not name.endswith(".json"), "missing full report body")
        require(regular(directory / name).strip(), "empty report body")

    for name in ("T078", "T079", "external-human"):
        report = document(directory / (name + ".json"))
        fields(report, ("schema", "source", "status", "reviewer", "observed_at", "report", "independent", "human"), name)
        require(report["schema"] == 1 and report["source"] == source and report["status"] == "PASS", name + " not passed on C")
        require(report["independent"] is True and isinstance(report["reviewer"], str)
                and report["reviewer"].strip(), name + " reviewer provenance absent")
        require(type(report["human"]) is bool and (name != "external-human" or report["human"]), "external human review absent")
        require(timestamp(report["observed_at"]) <= now(), "review timestamp is in the future")
        report_body(report["report"])
    live = document(directory / "live.json")
    fields(live, ("schema", "source", "version", "tracker_sha256", "observations"), "live report")
    tracker = regular(ROOT / "specs/001-tor-route/live-e2e/README.md")
    require(live["schema"] == 1 and live["source"] == source and live["version"] == tag
            and live["tracker_sha256"] == sha(tracker), "live tracker/source changed")
    rows = {line.split("|")[1].strip(): sha(line.encode()) for line in tracker.decode().splitlines()
            if line.startswith(("| F", "| R-"))}
    required = ["F1", "F2", "F3", "F4", "F5", "F7", *["R-" + str(i) for i in range(1, 9)]]
    fields(live["observations"], required, "live observations")
    artifacts = {k: v["sha256"] for k, v in candidate["artifacts"].items()}
    for name in required:
        observation = live["observations"][name]
        keys = ["status", "scope", "report", "contract_sha256", "artifact_sha256"]
        fields(observation, keys + (["coverage"] if name == "R-7" else []), name)
        require(observation["status"] == "PASS" and observation["scope"] == "exercised", name + " not exercised")
        require(observation["contract_sha256"] == rows[name], name + " contract differs")
        require(observation["artifact_sha256"] == artifacts, name + " artifacts differ")
        report_body(observation["report"])
        if name == "R-7":
            fields(observation["coverage"], ("routed-ipv6", "lan", "vps", "physical-nic", "hypervisor"), "R-7 coverage")
            require(all(v == "PASS" for v in observation["coverage"].values()), "R-7 scope is unmeasured")
    pending = [r["check"] for r in candidate.get("pending", []) if r["evidence"] == "cadence"]
    if pending:
        cadence = document(directory / "cadence.json")
        fields(cadence, ("schema", "source", "artifact_sha256", "results"), "cadence report")
        require(cadence["schema"] == 1 and cadence["source"] == source and cadence["artifact_sha256"] == artifacts,
                "cadence evidence source/artifacts differ")
        fields(cadence["results"], pending, "cadence results")
        for name, result in cadence["results"].items():
            fields(result, ("status", "report"), "cadence result")
            require(result["status"] == "PASS", "cadence suite not executed: " + name)
            report_body(result["report"])
    # These structural checks bind complete bytes, not an author's identity or
    # honesty. The protected approver must inspect provenance and full reports.
    return sha(canonical(index))


def timestamp(value):
    require(isinstance(value, str) and value.endswith("Z"), "timestamp must be UTC")
    result = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    require(result.tzinfo is not None, "timestamp lacks timezone")
    return result


def now():
    return dt.datetime.now(dt.timezone.utc)


def fresh_trust():
    policy = pins()
    selection = policy["trust_selection"]
    fields(selection, ("target_sha256", "target_length", "fresh_until", "bootstrap", "metadata"), "trust selection")
    root = policy["tools"]["trusted-root"]
    require(selection["target_sha256"] == root["sha256"] and selection["target_length"] == root["size"],
            "trust selection target differs")
    fields(selection["metadata"], ("15.root.json", "targets.json", "snapshot.json", "timestamp.json"), "trust metadata")
    for record in selection["metadata"].values():
        fields(record, ("version", "sha256", "size"), "trust metadata record")
        digest(record["sha256"])
        require(type(record["version"]) is int and record["version"] > 0
                and type(record["size"]) is int and record["size"] > 0, "malformed trust selection")
    require(now() < timestamp(selection["fresh_until"]), "trust selection is stale; reviewed source refresh required")
    tool("trusted-root")


def checked_signing_config():
    # Cosign v3 selects signing services from a file. Pin that file to C and
    # the same freshness cutoff as the reviewed trust root (Principle IV).
    policy = pins()
    config = policy["signing_config"]
    fields(config, ("mediaType", "caUrls", "rekorTlogUrls", "rekorTlogConfig", "tsaConfig"), "signing config")
    interval = {"start": "2026-10-11T00:00:00Z", "end": policy["trust_selection"]["fresh_until"]}
    require(timestamp(interval["start"]) <= now() < timestamp(interval["end"]), "signing service selection is stale")
    service = {"majorApiVersion": 1, "validFor": interval, "operator": "sigstore.dev"}
    require(config == {"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
                       "caUrls": [service | {"url": "https://fulcio.sigstore.dev"}],
                       "rekorTlogUrls": [service | {"url": "https://rekor.sigstore.dev"}],
                       "rekorTlogConfig": {"selector": "EXACT", "count": 1}, "tsaConfig": {}},
            "signing config differs from fixed Fulcio/Rekor service policy")
    return config


def api(path, *, method="GET", data=None, expected_status=None):
    require(path == "" or path.startswith("/") and not path.startswith("//"), "invalid API path")
    token = os.environ.get("GITHUB_TOKEN", "")
    require(token and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "canonical repository token/context required")
    headers = {"Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
               "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}
    request = urllib.request.Request(API + path, data=None if data is None else canonical(data),
                                     headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=60) as response:
        if expected_status is not None:
            require(response.status == expected_status,
                    "release write returned an unexpected status; reconcile manually")
        return decode(response.read(MAX_JSON + 1))


def approval_comment(pack):
    return ("Approve Stargate pack " + sha(canonical(pack)) + " source " + pack["source"]
            + " evidence " + pack["evidence_commit"] + " artifact " + str(pack["artifact_id"])
            + " prepare " + str(pack["prepare_run_id"]) + "/" + str(pack["prepare_run_attempt"]))


def protection(pack=None, approved=False):
    fresh_trust()
    policy = api("/environments/stargate-release")
    require(policy.get("name") == "stargate-release" and type(policy.get("id")) is int,
            "protected environment missing")
    require(policy.get("can_admins_bypass") is False, "administrator bypass is enabled or unverified")
    require(policy.get("deployment_branch_policy") == {"protected_branches": False, "custom_branch_policies": True},
            "environment must use custom tag-only protection")
    reviewers = [r for r in policy.get("protection_rules", []) if r.get("type") == "required_reviewers"]
    require(len(reviewers) == 1 and reviewers[0].get("prevent_self_review") is True,
            "required independent reviewers missing")
    allowed = {(r["reviewer"]["id"], r["reviewer"]["login"]) for r in reviewers[0].get("reviewers", [])
               if r.get("type") == "User"}
    require(allowed, "at least one configured direct human reviewer is required")
    branches = api("/environments/stargate-release/deployment-branch-policies?per_page=100")
    require(branches.get("total_count") == 1 and len(branches.get("branch_policies", [])) == 1,
            "environment tag policy is not singular")
    branch = branches["branch_policies"][0]
    require(branch.get("type") == "tag" and branch.get("name") == "v*", "environment allows other refs")
    if approved:
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        require(run_id.isdigit(), "promotion run ID missing")
        actor = os.environ.get("GITHUB_ACTOR")
        triggering_actor = os.environ.get("GITHUB_TRIGGERING_ACTOR")
        require(actor and triggering_actor, "promotion actors missing")
        approvals = api("/actions/runs/" + run_id + "/approvals")
        require(isinstance(approvals, list), "approval history unavailable")
        accepted = []
        for approval in approvals:
            if any(e.get("id") == policy["id"] for e in approval.get("environments", [])):
                user = approval.get("user", {})
                require(approval.get("state") == "approved", "non-approved environment history")
                require((user.get("id"), user.get("login")) in allowed
                        and user.get("login") not in (actor, triggering_actor), "approval is not an independent configured reviewer")
                require(approval.get("comment") == approval_comment(pack), "approval does not name exact source/evidence/artifact pack")
                accepted.append(approval)
        require(accepted, "protected approval is absent; data cannot self-approve")
    # Exclude changing API timestamps and links from the stable pack, while
    # retaining every policy property the gate actually relied upon.
    return {"id": policy["id"], "name": policy["name"], "can_admins_bypass": False,
            "reviewers": sorted([list(x) for x in allowed]), "prevent_self_review": True, "tag_policy": "v*"}


def file_hash(path):
    require(stat.S_ISREG(Path(path).lstat().st_mode), "expected regular file")
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def extract_artifact(archive, expected, output):
    archive, output = Path(archive), Path(output)
    require(archive.stat().st_size <= MAX_ARCHIVE and file_hash(archive) == digest(expected), "retained archive hash differs")
    require(not output.exists(), "artifact output already exists")
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        require(len(members) <= 50000 and sum(m.file_size for m in members) <= MAX_UNPACKED, "archive exceeds bound")
        seen = set()
        for member in members:
            name = member.filename.rstrip("/") if member.is_dir() else member.filename
            safe_path(name)
            require(name not in seen, "duplicate archive path")
            seen.add(name)
            mode = member.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), "archive contains special file")
            require(not member.flag_bits & 1, "encrypted artifact is unsupported")
        files = {m.filename for m in members if not m.is_dir()}
        require(all(not any(str(parent) in files for parent in PurePosixPath(name).parents)
                    for name in seen), "archive file/directory collision")
        require_space(output.parent, sum(m.file_size for m in members))
        output.mkdir(parents=True)
        try:
            for member in members:
                target = output / member.filename
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(member) as source, target.open("xb") as destination:
                        shutil.copyfileobj(source, destination, 1024 * 1024)
                    target.chmod(0o644)
        except Exception:
            shutil.rmtree(output)
            raise


class DownloadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        require(urllib.parse.urlparse(newurl).scheme == "https", "insecure download redirect")
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        # GitHub artifact storage uses signed redirects. Never forward the
        # repository credential to storage or an unrelated download origin.
        redirected.remove_header("Authorization")
        return redirected


def require_space(directory, additional_bytes):
    directory = Path(directory)
    while not directory.exists():
        directory = directory.parent
    require(shutil.disk_usage(directory).free >= additional_bytes + DISK_RESERVE,
            "insufficient disk space for bounded stage and reserve")


def download(url, path, maximum, *, token=None):
    require(urllib.parse.urlparse(url).scheme == "https", "download must use HTTPS")
    headers = {} if token is None else {"Authorization": "Bearer " + token}
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(DownloadRedirect())
    with opener.open(request, timeout=60) as source, Path(path).open("xb") as dest:
        count = 0
        while True:
            data = source.read(1024 * 1024)
            if not data:
                break
            count += len(data)
            require(count <= maximum, "download exceeds bound")
            dest.write(data)


def install_tools(purpose):
    require(sys.platform == "linux" and os.uname().machine == "x86_64", "tools require Linux amd64")
    selected = {"prepare": ("docker-compose", "docker-buildx"),
                "validate": ("trusted-root", "docker-compose"),
                "promote": ("cosign", "crane", "trusted-root", "docker-compose"),
                "install": ("cosign", "trusted-root", "docker-compose")}[purpose]
    TOOLS.mkdir(parents=True, exist_ok=True)
    for name in selected:
        record = pins()["tools"][name]
        filename = "trusted-root.json" if name == "trusted-root" else name
        output = TOOLS / filename
        if output.exists():
            tool(name)
            continue
        archive = TOOLS / (name + ".download")
        if not archive.exists():
            require_space(TOOLS, record["size"] * 2)
            download(record["url"], archive, record["size"])
        require(archive.stat().st_size == record["size"] and file_hash(archive) == record["sha256"], "downloaded tool hash differs")
        if record.get("member"):
            with tarfile.open(archive, "r:gz") as tf:
                members = [m for m in tf.getmembers() if m.name == record["member"]]
                require(len(members) == 1 and members[0].isfile() and members[0].size <= 256 * 1024**2,
                        "invalid tool archive member")
                with tf.extractfile(members[0]) as source, output.open("xb") as destination:
                    shutil.copyfileobj(source, destination)
        else:
            shutil.copyfile(archive, output)
        output.chmod(0o644 if name == "trusted-root" else 0o755)
        tool(name)


def fetch_evidence(evidence_commit, tag, output):
    commit(evidence_commit)
    version(tag)
    info = api("/git/commits/" + evidence_commit)
    require(info.get("sha") == evidence_commit, "evidence commit differs")
    tree = info["tree"]["sha"]
    for directory in ("release-evidence", tag):
        entries = api("/git/trees/" + commit(tree))
        require(entries.get("truncated") is False, "evidence tree is truncated")
        found = [r for r in entries["tree"] if r["path"] == directory and r["type"] == "tree" and r["mode"] == "040000"]
        require(len(found) == 1, "fixed evidence directory missing")
        tree = found[0]["sha"]
    entries = api("/git/trees/" + commit(tree) + "?recursive=1")
    require(entries.get("truncated") is False and len(entries["tree"]) <= 128, "evidence tree exceeds bound")
    output.mkdir(parents=True)
    total = 0
    for entry in entries["tree"]:
        safe_path(entry["path"])
        require(entry["type"] == "blob" and entry["mode"] == "100644", "evidence must be flat regular non-executable blobs")
        require("/" not in entry["path"], "evidence directory must be flat")
        blob = api("/git/blobs/" + commit(entry["sha"]))
        require(blob.get("encoding") == "base64" and blob.get("sha") == entry["sha"], "evidence blob identity differs")
        data = base64.b64decode("".join(blob["content"].split()), validate=True)
        total += len(data)
        require(len(data) <= MAX_JSON and total <= 64 * 1024**2, "evidence bytes exceed bound")
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == entry["sha"], "evidence Git blob hash differs")
        (output / entry["path"]).write_bytes(data)


# These are deferred observations, never successes. Missing prerequisites in
# any other gate refuse preparation; evidence cannot expand this policy.
CADENCE_GATES = {
    "contract:operational_logs_test.sh": ("Docker operational capture; set STARGATE_TEST_TAGS=docker", "F2"),
    "contract:t162_enforcement_test.sh": ("T162 docker packet and AppArmor profile falsifiers (run with STARGATE_TEST_TAGS=docker)", "F7"),
    "contract:init_t198_test.sh": ("T198 real apparmor_parser leg (needs apparmor_parser and AppArmor af_unix features)", "F7"),
    "contract:inter_plane_wire_test.sh": ("inter-plane runtime rows not exercised: ", "F2"),
}

# These two Go functions are fixture servers started by Maven's Java↔Go
# contracts. In the ordinary Go suite their intentional skip is expected only
# when the owning Maven gate passed (Principle VII); other test skips refuse.
JAVA_OWNED_GO_FIXTURES = {
    "test SKIP: github.com/zcat-app/stargate/data-plane/cmd/tor-observer.TestJavaClientInteropFixture — launched by the Java observer client contract test",
    "test SKIP: github.com/zcat-app/stargate/data-plane/internal/controlclient.TestJavaReloadInteropFixture — fixture mode requires T159_JAVA_INTEROP_DIR",
}


def check_verify(path):
    log = regular(path, 128 * 1024**2).decode()
    expected = ["license-headers", "ground-check", "shell-quality", "go-workspace", "extension-tests", "mvnw-verify"]
    expected += ["contract:" + p.name for p in (ROOT / "tests/contract").rglob("*")
                 if p.is_file() and (p.name.endswith("_test.sh") or p.suffix == ".bats")]
    expected += ["repro:" + p.name for p in (ROOT / "tests/reproducibility").glob("*.sh")]
    found, passed, pending = [], set(), []
    for state, name, note in re.findall(r"^  \[(PASS|SKIP|FAIL)\] (\S+)(?: — ([^\n]*))?\s*$", log, re.M):
        found.append(name)
        if state == "PASS":
            passed.add(name)
        require(state != "FAIL", "failed verification gate: " + name)
        if state == "SKIP":
            require(name in CADENCE_GATES, "required gate skipped: " + name)
            reason, evidence = CADENCE_GATES[name]
            require(note == reason or (name == "contract:inter_plane_wire_test.sh" and note.startswith(reason)
                    and re.fullmatch(r"R[1-9](?: R[1-9])*", note[len(reason):])), "unapproved skip reason: " + name)
            pending.append({"check": name, "evidence": evidence})
    require(sorted(found) == sorted(expected), "missing, duplicate or unexpected verification gate")
    for line in log.splitlines():
        if re.match(r"^\s+test SKIP:", line):
            if line.strip() in JAVA_OWNED_GO_FIXTURES and "mvnw-verify" in passed:
                continue
            raise Refusal("individual test skipped: " + line.strip())
        match = re.match(r"^  (SKIP(?:\[(docker|live|release)\])?)\s+go:([^: ]+):([^ ]+)\s+(.*)$", line)
        if not match:
            continue
        _, cadence, module, package, counts = match.groups()
        safe_path(module)
        module_text = regular(ROOT / module / "go.mod").decode()
        module_name = re.search(r"^module\s+(\S+)$", module_text, re.M).group(1)
        require(package == module_name or package.startswith(module_name + "/"), "Go package outside source module")
        relative = package[len(module_name):].lstrip("/")
        safe_path(relative or "module-root")
        directory = ROOT / module / relative
        tests = list(directory.glob("*_test.go"))
        if not cadence:
            require(not tests and counts == "pass=0 fail=0 skip=0", "required Go package skipped")
            continue
        require(tests and any(re.search(r"^//go:build .*\b" + cadence + r"\b", p.read_text(), re.M) for p in tests),
                "Go cadence does not match source tests")
        require(counts.startswith("— named " + cadence + " job (all files //go:build " + cadence + ")"),
                "Go cadence execution skipped")
        # Tagged suites are independently executed against retained bytes and
        # require exact named reports in E; F1/F2 alone do not imply they ran.
        pending.append({"check": "go:" + module + ":" + package, "evidence": "cadence"})
    return pending


def validate_buildkit_provenance(predicate, source):
    build = predicate.get("buildDefinition")
    require(type(build) is dict and
            build.get("buildType") == "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
            "unsupported BuildKit provenance build type")
    external = build.get("externalParameters")
    require(type(external) is dict and type(external.get("configSource")) is dict and
            type(external.get("request")) is dict,
            "BuildKit provenance lacks local build parameters")
    config = external["configSource"]
    require(type(config.get("path")) is str and config["path"] and
            "uri" not in config and "digest" not in config,
            "BuildKit provenance is not a local Dockerfile build")
    safe_path(config["path"])
    request = external["request"]
    locals_ = request.get("locals")
    require(request.get("frontend") == "dockerfile.v0" and type(locals_) is list and
            len(locals_) == 2 and all(type(item) is dict and type(item.get("name")) is str
                                      for item in locals_) and
            {item["name"] for item in locals_} == {"context", "dockerfile"},
            "BuildKit provenance local context differs")
    args = request.get("args")
    nested = request.get("root")
    require(type(args) is dict and
            args.get("label:org.opencontainers.image.revision") == source and
            type(nested) is dict and type(nested.get("request")) is dict and
            type(nested["request"].get("args")) is dict and
            nested["request"]["args"].get("vcs:revision") == source,
            "BuildKit provenance revision hints differ from reviewed source")
    details = predicate.get("runDetails")
    require(type(details) is dict and type(details.get("metadata")) is dict,
            "BuildKit provenance run metadata is malformed")
    buildkit = details["metadata"].get("buildkit_metadata")
    if buildkit is not None:
        require(type(buildkit) is dict, "BuildKit provenance metadata is malformed")
        vcs = buildkit.get("vcs")
        if vcs is not None:
            require(type(vcs) is dict and vcs.get("revision") == source,
                    "BuildKit provenance VCS metadata conflicts with reviewed source")
    dependencies = build.get("resolvedDependencies")
    require(type(dependencies) is list and all(type(item) is dict and
            type(item.get("uri")) is str for item in dependencies),
            "BuildKit provenance dependencies are malformed")
    for item in dependencies:
        if re.match(r"^(?:(?:git\+)?(?:https?|ssh|git)://(?:git@)?github\.com/|git@github\.com:)"
                    r"zcat-app/stargate(?:\.git)?(?:#|$)", item["uri"], re.IGNORECASE):
            require(type(item.get("digest")) is dict and item["digest"].get("sha1") == source,
                    "BuildKit provenance Git material conflicts with reviewed source")


def inspect_oci(directory, source):
    directory = Path(directory)
    commit(source)
    require(document(directory / "oci-layout") == {"imageLayoutVersion": "1.0.0"}, "unsupported OCI layout")
    outer = document(directory / "index.json")
    require(outer.get("schemaVersion") == 2 and len(outer.get("manifests", [])) == 1, "OCI layout must have one retained root descriptor")
    root = outer["manifests"][0]
    seen = set()

    def blob(descriptor):
        require(isinstance(descriptor, dict) and isinstance(descriptor.get("digest"), str)
                and descriptor["digest"].startswith("sha256:"), "unsupported OCI digest")
        checksum = digest(descriptor["digest"][7:])
        path = directory / "blobs/sha256" / checksum
        require(type(descriptor.get("size")) is int and 0 <= descriptor["size"] <= MAX_ARCHIVE, "invalid OCI size")
        require(path.stat().st_size == descriptor["size"] and file_hash(path) == checksum, "OCI blob hash/length differs")
        return path

    manifests = []

    def walk(descriptor, depth=0):
        require(depth < 8 and len(seen) < 10000, "OCI graph exceeds bound")
        path = blob(descriptor)
        if descriptor["digest"] in seen:
            return
        seen.add(descriptor["digest"])
        media = descriptor.get("mediaType", "")
        if media in ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"):
            obj = document(path)
            require(obj.get("schemaVersion") == 2 and obj.get("manifests"), "empty OCI index")
            for child in obj["manifests"]:
                walk(child, depth + 1)
        elif media in ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"):
            obj = document(path)
            require(obj.get("schemaVersion") == 2 and isinstance(obj.get("layers"), list), "invalid OCI image manifest")
            blob(obj["config"])
            for layer in obj["layers"]:
                blob(layer)
            manifests.append((descriptor, obj))
        else:
            raise Refusal("unsupported OCI root media type")
    walk(root)
    runtime = [(d, m) for d, m in manifests if d.get("annotations", {}).get("vnd.docker.reference.type") != "attestation-manifest"]
    require(len(runtime) == 1, "expected one runtime image")
    descriptor, manifest = runtime[0]
    config = document(blob(manifest["config"]))
    require(config.get("os") == "linux" and config.get("architecture") == "amd64", "runtime OCI platform differs")
    require(config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") == source,
            "runtime OCI source revision differs")
    predicates = set()
    for attestation, body in manifests:
        if attestation is descriptor:
            continue
        require(attestation.get("annotations", {}).get("vnd.docker.reference.digest") == descriptor["digest"],
                "attestation image subject differs")
        # BuildKit's in-toto statements can carry an empty subject array. The
        # OCI manifest subject (image-spec manifest.md) and index descriptor
        # annotation must both identify this hashed runtime descriptor.
        require(body.get("subject") == {key: descriptor[key] for key in ("mediaType", "digest", "size")},
                "attestation manifest subject differs from runtime manifest")
        for layer in body["layers"]:
            require(layer.get("mediaType") == "application/vnd.in-toto+json", "unsupported attestation layer")
            statement = document(blob(layer))
            require(statement.get("_type") in ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"), "unsupported attestation statement")
            subjects = statement.get("subject")
            require(isinstance(subjects, list) and (not subjects or
                    (len(subjects) == 1 and isinstance(subjects[0], dict) and
                     subjects[0].get("digest", {}).get("sha256") == descriptor["digest"][7:])),
                    "attestation statement subject conflicts with runtime manifest")
            predicate = statement.get("predicateType")
            require(predicate in ("https://spdx.dev/Document", "https://slsa.dev/provenance/v1"), "unsupported build attestation")
            require(isinstance(statement.get("predicate"), dict) and statement["predicate"], "empty build attestation")
            if "slsa.dev" in predicate:
                validate_buildkit_provenance(statement["predicate"], source)
            predicates.add("provenance" if "slsa.dev" in predicate else "sbom")
    require(predicates == {"provenance", "sbom"}, "retained OCI lacks SBOM or provenance")
    return {"digest": root["digest"], "runtime_digest": descriptor["digest"],
            "layers": manifest["layers"], "platform": "linux/amd64"}


def image_payload(directory, info, service):
    prefixes = {"stargate-dp": ("opt/stargate/stargate-proxy",),
                "stargate-control": ("opt/stargate/",),
                "tor-observer": ("opt/stargate/tor-observer",),
                "tor": ("usr/local/bin/tor-health-publisher", "var/lib/dpkg/status")}[service]
    result = {}
    for layer in info["layers"]:
        path = Path(directory) / "blobs/sha256" / layer["digest"][7:]
        require(layer["mediaType"] in ("application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar",
                                      "application/vnd.docker.image.rootfs.diff.tar.gzip"), "unsupported layer compression")
        with tarfile.open(path, "r:*") as tf:
            count = 0
            for member in tf:
                count += 1
                require(count <= 250000, "layer file count exceeds bound")
                name = member.name.removeprefix("./").rstrip("/")
                if not name:
                    continue
                safe_path(name)
                parent, _, leaf = name.rpartition("/")
                if leaf == ".wh..wh..opq":
                    result = {k: v for k, v in result.items() if not k.startswith(parent + "/")}
                elif leaf.startswith(".wh."):
                    target = (parent + "/" if parent else "") + leaf[4:]
                    result = {k: v for k, v in result.items() if k != target and not k.startswith(target + "/")}
                elif any(name == p or (p.endswith("/") and name.startswith(p)) for p in prefixes) and not member.isdir():
                    require(member.isfile() and 0 < member.size <= MAX_PAYLOAD_BYTES, "invalid shipped image payload")
                    total = sum(len(v[0]) for k, v in result.items() if k != name)
                    require(total + member.size <= MAX_PAYLOAD_BYTES, "aggregate shipped payload exceeds bound")
                    result[name] = (tf.extractfile(member).read(), member.mode & 0o777)
    require(result, "image payload missing")
    return result


def workflow_identity(source, tag, *, preparation=False):
    commit(source)
    version(tag)
    expected = {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_SHA": source, "GITHUB_WORKFLOW_SHA": source,
                "GITHUB_REF": "refs/tags/" + tag, "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_WORKFLOW_REF": REPOSITORY + "/.github/workflows/release.yml@refs/tags/" + tag}
    require(all(os.environ.get(k) == v for k, v in expected.items()), "workflow is not the exact existing source tag")
    require(all(os.environ.get(k, "").isdigit() for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "workflow run identity missing")
    if preparation:
        require(not any(k.startswith("ACTIONS_ID_TOKEN_") for k in os.environ), "preparation has signing authority")
        require(not any(k.startswith("STARGATE_SKIP_") or k in ("STARGATE_VERIFY_REPRO_ONLY", "STARGATE_TEST_TAGS", "STARGATE_RUN_NETWORK_TESTS")
                        for k in os.environ), "preparation verification override present")


def retained_metadata(args):
    source, tag = commit(args.source), version(args.version)
    require(all(type(v) is int and v > 0 for v in (args.artifact_id, args.prepare_run_id, args.prepare_run_attempt)), "invalid retained artifact identity")
    artifact = api("/actions/artifacts/" + str(args.artifact_id))
    run_info = api("/actions/runs/" + str(args.prepare_run_id) + "/attempts/" + str(args.prepare_run_attempt))
    require(artifact.get("id") == args.artifact_id and artifact.get("expired") is False
            and timestamp(artifact["expires_at"]) > now(), "artifact expired or changed")
    require(type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE,
            "artifact archive exceeds bound")
    require(artifact.get("name") == "stargate-" + tag + "-" + source + "-" + str(args.prepare_run_id) + "-" + str(args.prepare_run_attempt),
            "artifact name does not bind preparation identity")
    require(artifact.get("workflow_run", {}).get("id") == args.prepare_run_id
            and artifact["workflow_run"].get("head_sha") == source, "artifact belongs to different run/source")
    expected = {"id": args.prepare_run_id, "run_attempt": args.prepare_run_attempt, "head_sha": source,
                "head_branch": tag, "path": ".github/workflows/release.yml", "event": "workflow_dispatch",
                "status": "completed", "conclusion": "success"}
    require(all(run_info.get(k) == v for k, v in expected.items()), "preparation run does not match successful exact source/attempt")
    require(isinstance(artifact.get("digest"), str) and artifact["digest"].startswith("sha256:"), "retained archive digest unavailable")
    digest(artifact["digest"][7:])
    return {k: artifact[k] for k in ("id", "name", "size_in_bytes", "digest", "expires_at")}


def tor_packages(payload):
    status = payload["var/lib/dpkg/status"][0].decode()
    rows = []
    for paragraph in status.split("\n\n"):
        fields_ = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                fields_[key] = value
        if fields_.get("Status") == "install ok installed":
            rows.append("amd64 " + fields_["Package"] + " " + fields_["Version"] + " " + fields_["Architecture"])
    expected = sorted(" ".join(line.split()[:4]) for line in regular(ROOT / "sidecars/tor/package-closure.lock").decode().splitlines()
                      if line.startswith("amd64 "))
    require(expected and sorted(rows) == expected, "retained Tor package set differs from source closure")
    return sorted(rows)


def package_tar(output, payload):
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as tf:
        for name, (data, mode) in sorted(payload.items()):
            safe_path(name)
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.mtime = len(data), mode, 0
            member.uid = member.gid = 0
            tf.addfile(member, io.BytesIO(data))


def prepare(args):
    workflow_identity(args.source, args.version, preparation=True)
    source_files = source_identity(args.source, args.version)
    require(not args.output.exists(), "preparation output already exists")
    buildx = tool("docker-buildx")
    compose_tool = tool("docker-compose")
    require(run(["go", "version"]).decode().startswith("go version go1.26.3 "), "release Go toolchain differs")
    args.output.mkdir(parents=True)
    builder = "stargate-release-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    env = dict(os.environ)
    # Use only the selected plugins, leaving the host's installed plugins and
    # Docker configuration unchanged. No cache restore crosses source runs.
    config = ROOT / "target/release-docker"
    (config / "cli-plugins").mkdir(parents=True, exist_ok=True)
    for name, executable in (("docker-buildx", buildx), ("docker-compose", compose_tool)):
        link = config / "cli-plugins" / name
        require(not link.exists(), "release Docker plugin directory already populated")
        link.symlink_to(executable)
    env.update(DOCKER_CONFIG=str(config), BUILDX_BUILDER=builder, STARGATE_GROUND_ONLINE="1", STARGATE_VERIFY_REPRO="1",
               STARGATE_EXTENSION_RUNNER="release")
    verifier_env = env | {"BUILDX_BUILDER": "default"}
    # The existing verifier's Docker builds are immediately consumed through
    # docker create/run. Its local Docker driver loads tags and shares the
    # runner's host-loopback proxy used by the Tor rollback control; the
    # private container builder below is only for retained OCI exports.
    driver = run([buildx, "inspect", "default"], env=verifier_env).decode()
    require(re.search(r"(?m)^Driver:[ \t]+docker[ \t]*$", driver),
            "local Docker builder must load verifier images")
    run([buildx, "create", "--name", builder, "--driver", "docker-container", "--driver-opt", "image=" + pins()["buildkit"]], env=env)
    try:
        # The real verifier, including every reproducibility sibling, runs on
        # the complete C. The retained log is parsed, not merely its exit code.
        (args.output / "logs").mkdir()
        run(["bash", "scripts/verify.sh"], env=verifier_env, log=args.output / "logs/verify-command.log", timeout=180 * 60)
        shutil.copyfile(ROOT / "target/verify.log", args.output / "verify.log")
        pending = check_verify(args.output / "verify.log")
        run([buildx, "--builder", builder, "prune", "--all", "--force"], env=env)
        paths = {"stargate-dp": "data-plane/Dockerfile", "stargate-control": "control-plane/Dockerfile",
                 "tor": "sidecars/tor/Dockerfile", "tor-observer": "sidecars/tor-observer/Dockerfile"}
        images, repro = {}, {}
        with tempfile.TemporaryDirectory(prefix="stargate-independent-") as temporary:
            for service, recipe in paths.items():
                payloads = []
                for ordinal in (0, 1):
                    directory = (args.output / "oci" / service if ordinal == 0 else Path(temporary) / service)
                    directory.parent.mkdir(parents=True, exist_ok=True)
                    run([buildx, "--builder", builder, "build", "--no-cache", "--platform", "linux/amd64",
                         "--file", recipe, "--label", "org.opencontainers.image.revision=" + args.source,
                         "--provenance=mode=max", "--attest", "type=sbom,generator=" + pins()["sbom_generator"],
                         "--output", "type=oci,dest=" + str(directory) + ",tar=false,compression=gzip", "."], env=env,
                        log=args.output / "logs" / (service + "-" + str(ordinal) + ".log"), timeout=3600)
                    info = inspect_oci(directory, args.source)
                    payloads.append(image_payload(directory, info, service))
                    if ordinal == 0:
                        images[service] = "ghcr.io/zcat-app/" + SERVICES[service] + "@" + info["digest"]
                    # Only this job's private builder is eligible for cleanup.
                    # The exported complete OCI graph is already retained.
                    run([buildx, "--builder", builder, "prune", "--all", "--force"], env=env)
                if service == "tor":
                    packages = tor_packages(payloads[0])
                    require(tor_packages(payloads[1]) == packages, "Tor package comparison differs")
                    compare = ["usr/local/bin/tor-health-publisher"]
                    write_json(args.output / "tor-packages.json", packages)
                else:
                    require(set(payloads[0]) == set(payloads[1]), "shipped payload paths differ")
                    compare = list(payloads[0])
                require(all(payloads[0][p] == payloads[1][p] for p in compare), "independent shipped payloads differ: " + service)
                shutil.rmtree(Path(temporary) / service)
                repro[service] = {"tier": "package-set-and-publisher-bytes" if service == "tor" else "all-shipped-payload-bytes",
                                  "files": {p: {"sha256": sha(payloads[0][p][0]), "mode": oct(payloads[0][p][1])} for p in sorted(compare)}}
                if service == "stargate-dp":
                    (args.output / "stargate-proxy-linux-amd64").write_bytes(payloads[0]["opt/stargate/stargate-proxy"][0])
                elif service == "stargate-control":
                    cp = {name.removeprefix("opt/stargate/"): value for name, value in payloads[0].items()}
                    require("quarkus-run.jar" in cp and "entrypoint.sh" in cp
                            and all(any(p.startswith(d + "/") for p in cp) for d in ("app", "lib", "quarkus")), "full JVM fast-jar tree missing")
                    package_tar(args.output / "stargate-control.tar", cp)
            arm = []
            for ordinal in (0, 1):
                output = Path(temporary) / ("arm64-" + str(ordinal))
                run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", output, "./cmd/stargate-proxy"],
                    cwd=ROOT / "data-plane", env=env | {"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOCACHE": str(Path(temporary) / ("go-cache-" + str(ordinal)))})
                arm.append(regular(output, 256 * 1024**2))
            require(arm[0] and arm[0] == arm[1], "arm64 cross-built bytes differ")
            (args.output / "stargate-proxy-linux-arm64").write_bytes(arm[0])
            repro["arm64"] = {"tier": "cross-build-only-no-runtime-acceptance", "sha256": sha(arm[0])}
        # Each invocation builds a fresh no-cache helper and packages a fresh
        # source copy. Compare the delivered ZIP itself, not an earlier test's
        # output that the verifier discarded (Principle VII).
        run([sys.executable, ROOT / "scripts/release.py", "package-extension", "--output", args.output / "stargate-extension.zip"], env=env)
        with tempfile.TemporaryDirectory(prefix="stargate-extension-repeat-") as temporary:
            repeat = Path(temporary) / "stargate-extension.zip"
            run([sys.executable, ROOT / "scripts/release.py", "package-extension", "--output", repeat], env=env)
            require(file_hash(args.output / "stargate-extension.zip") == file_hash(repeat),
                    "delivered extension archive differs across pinned runs")
        repro["extension"] = {"tier": "pinned-two-run-byte-identity",
                              "sha256": file_hash(args.output / "stargate-extension.zip")}
        write_json(args.output / "compose.json", compose(images))
        run(["git", "archive", "--format=tar", "--output=" + str(args.output / "source.tar"), args.source])
        write_json(args.output / "reproducibility.json", repro)
        require(source_identity(args.source, args.version) == source_files, "preparation changed source")
        candidate = {"schema": 1, "source": args.source, "version": args.version, "platform": "linux/amd64",
                     "images": images, "source_files": source_files, "artifacts": inventory(args.output),
                     "pending": pending, "prepare_run_id": int(os.environ["GITHUB_RUN_ID"]),
                     "prepare_run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"])}
        write_json(args.output / "candidate.json", candidate)
    finally:
        run([buildx, "rm", builder], env=env)


def reject_existing_version(tag):
    try:
        api("/releases/tags/" + version(tag))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return
        raise
    raise Refusal("version already has a release or draft; version reuse requires manual resolution")


def remote_tag_commit(tag):
    # /commits/<name> accepts a same-named branch. Only the Git refs/tags
    # namespace proves the reviewed version tag still exists (Principle IV).
    version(tag)
    reference = api("/git/ref/tags/" + urllib.parse.quote(tag, safe=""))
    require(type(reference) is dict and reference.get("ref") == "refs/tags/" + tag and
            type(reference.get("object")) is dict, "remote version tag is missing or malformed")
    target = reference["object"]
    for depth in range(5):
        require(type(target) is dict and type(target.get("sha")) is str and
                target.get("type") in ("commit", "tag"), "remote version tag target is malformed")
        oid = commit(target["sha"])
        if target["type"] == "commit":
            return oid
        tagged = api("/git/tags/" + oid)
        require(type(tagged) is dict and tagged.get("sha") == oid and
                type(tagged.get("tag")) is str and tagged["tag"] and
                (depth != 0 or tagged["tag"] == tag) and type(tagged.get("object")) is dict,
                "annotated version tag is malformed or mismatched")
        target = tagged["object"]
    raise Refusal("annotated version tag nesting exceeds bound")


def require_remote_tag(source, tag):
    require(remote_tag_commit(tag) == source, "remote version tag no longer points to reviewed source")


def workflow_tree_at(root):
    current = commit(root)
    for name in (".github", "workflows"):
        listing = api("/git/trees/" + current)
        require(type(listing) is dict and listing.get("sha") == current and
                listing.get("truncated") is False and type(listing.get("tree")) is list,
                "workflow tree lookup is incomplete")
        entries = listing["tree"]
        require(all(type(entry) is dict and type(entry.get("path")) is str and
                    type(entry.get("type")) is str and type(entry.get("mode")) is str and
                    type(entry.get("sha")) is str and re.fullmatch(r"[0-9a-f]{40}", entry["sha"])
                    for entry in entries) and
                len({entry["path"] for entry in entries}) == len(entries),
                "workflow tree entries are malformed or duplicated")
        matches = [entry for entry in entries if entry["path"] == name]
        require(len(matches) == 1 and matches[0]["type"] == "tree" and
                matches[0]["mode"] == "040000", "workflow subtree missing or changed type")
        current = matches[0]["sha"]
    return current


def require_default_workflows(source, repository):
    # GITHUB_TOKEN cannot modify workflows. GitHub may reject release writes
    # when the tag's workflows differ from default; compare exact Git trees
    # before irreversible registry work (Principle IV).
    branch = repository.get("default_branch")
    require(type(branch) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", branch)
            and ".." not in branch and "//" not in branch,
            "default branch identity unavailable")
    tagged = api("/git/commits/" + commit(source))
    require(type(tagged) is dict and tagged.get("sha") == source and
            type(tagged.get("tree")) is dict and type(tagged["tree"].get("sha")) is str,
            "reviewed source tree identity unavailable")
    source_tree = commit(tagged["tree"]["sha"])
    default = api("/commits/" + urllib.parse.quote(branch, safe=""))
    require(type(default) is dict and type(default.get("sha")) is str and
            type(default.get("commit")) is dict and type(default["commit"].get("tree")) is dict and
            type(default["commit"]["tree"].get("sha")) is str,
            "default branch commit/tree identity unavailable")
    commit(default["sha"])
    default_tree = commit(default["commit"]["tree"]["sha"])
    require(workflow_tree_at(source_tree) == workflow_tree_at(default_tree),
            "reviewed workflows differ from current default branch; GITHUB_TOKEN cannot publish this release")


def reject_existing_draft_or_release(source, tag):
    # The published REST lookup omits drafts. Query the exact tag through
    # GraphQL under this protected job's push-capable token (Principle IV).
    repository = api("")
    require(type(repository) is dict and repository.get("full_name") == REPOSITORY and
            type(repository.get("id")) is int and repository["id"] > 0 and
            type(repository.get("permissions")) is dict and
            repository["permissions"].get("push") is True,
            "promotion token lacks verified push access for draft visibility")
    require_default_workflows(source, repository)
    token = os.environ.get("GITHUB_TOKEN", "")
    require(token and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY,
            "canonical repository token/context required")
    query = ("query($owner:String!,$name:String!,$tag:String!){"
             "repository(owner:$owner,name:$name){nameWithOwner "
             "release(tagName:$tag){tagName isDraft}}}")
    request = urllib.request.Request("https://api.github.com/graphql",
        data=canonical({"query": query, "variables": {"owner": "zcat-app", "name": "stargate", "tag": tag}}),
        headers={"Accept": "application/json", "Authorization": "Bearer " + token,
                 "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=60) as response:
        require(response.status == 200, "exact-tag release lookup did not return HTTP 200")
        result = decode(response.read(MAX_JSON + 1))
    require(type(result) is dict and "errors" not in result and type(result.get("data")) is dict,
            "exact-tag release lookup failed or returned GraphQL errors")
    found = result["data"].get("repository")
    require(type(found) is dict and found.get("nameWithOwner") == REPOSITORY and "release" in found,
            "exact-tag release lookup returned an incomplete repository")
    release = found["release"]
    if release is not None:
        require(type(release) is dict and release.get("tagName") == tag and
                type(release.get("isDraft")) is bool,
                "exact-tag release lookup returned a malformed or conflicting release")
        raise Refusal("version already has a release or draft; version reuse requires manual resolution")
    # This second exact-tag lookup independently catches a published release
    # or a conflicting GraphQL/REST observation. Neither read reserves a tag.
    reject_existing_version(tag)


def verify_source_archive(path, source_files):
    seen = set()
    with tarfile.open(path, "r:") as tf:
        for member in tf:
            name = member.name.removeprefix("./")
            if member.isdir():
                continue
            safe_path(name)
            require(member.isfile() and name not in seen and name in source_files,
                    "source archive contains an unexpected entry")
            seen.add(name)
            record = source_files[name]
            require(member.size <= MAX_JSON and
                    ("100755" if member.mode & 0o111 else "100644") == record["mode"],
                    "source archive file mode or size differs")
            data = tf.extractfile(member).read(MAX_JSON + 1)
            require(len(data) == member.size and sha(data) == record["sha256"],
                    "source archive bytes differ from C")
    require(seen == set(source_files), "source archive is incomplete")


def verify_control_archive(path, payload):
    expected = {name.removeprefix("opt/stargate/"): pair for name, pair in payload.items()}
    require("quarkus-run.jar" in expected and "entrypoint.sh" in expected and
            all(any(p.startswith(d + "/") for p in expected) for d in ("app", "lib", "quarkus")),
            "full JVM fast-jar payload missing")
    seen = set()
    with tarfile.open(path, "r:") as tf:
        for member in tf:
            name = member.name.removeprefix("./")
            if member.isdir():
                continue
            safe_path(name)
            require(member.isfile() and name in expected and name not in seen,
                    "JVM archive contains an unexpected entry")
            seen.add(name)
            data, mode = expected[name]
            require(member.size == len(data) and member.mode & 0o777 == mode and
                    tf.extractfile(member).read(len(data) + 1) == data,
                    "JVM archive differs from retained image payload")
    require(seen == set(expected), "JVM archive omits shipped fast-jar files")


def validate_retained_candidate(retained, source, tag, source_files):
    retained = Path(retained)
    candidate_path = retained / "candidate.json"
    candidate = document(candidate_path)
    fields(candidate, ("schema", "source", "version", "platform", "images", "source_files", "artifacts",
                       "pending", "prepare_run_id", "prepare_run_attempt"), "candidate")
    require(type(candidate["schema"]) is int and candidate["schema"] == 1 and candidate["source"] == source
            and candidate["version"] == tag and candidate["platform"] == "linux/amd64"
            and candidate["source_files"] == source_files, "retained candidate source differs")
    require(type(candidate["prepare_run_id"]) is int and candidate["prepare_run_id"] > 0
            and type(candidate["prepare_run_attempt"]) is int and candidate["prepare_run_attempt"] > 0,
            "retained candidate run is malformed")
    check_inventory(retained, candidate["artifacts"], excluded=("candidate.json",))
    require(candidate["pending"] == check_verify(retained / "verify.log"), "retained verification accounting differs")
    image_map(candidate["images"])
    require(document(retained / "compose.json") == compose(candidate["images"]), "retained Compose differs")
    verify_source_archive(retained / "source.tar", source_files)
    repro = document(retained / "reproducibility.json")
    fields(repro, (*SERVICES, "arm64", "extension"), "reproducibility records")
    for service in SERVICES:
        info = inspect_oci(retained / "oci" / service, source)
        require(candidate["images"][service].endswith("@" + info["digest"]), "retained image digest differs")
        payload = image_payload(retained / "oci" / service, info, service)
        compared = (["usr/local/bin/tor-health-publisher"] if service == "tor" else sorted(payload))
        fields(repro[service], ("tier", "files"), service + " reproducibility")
        require(repro[service]["tier"] == ("package-set-and-publisher-bytes" if service == "tor"
                else "all-shipped-payload-bytes") and
                repro[service]["files"] == {p: {"sha256": sha(payload[p][0]), "mode": oct(payload[p][1])}
                                             for p in sorted(compared)}, "reproducibility record differs from shipped payload")
        if service == "stargate-dp":
            require(regular(retained / "stargate-proxy-linux-amd64", MAX_PAYLOAD_BYTES)
                    == payload["opt/stargate/stargate-proxy"][0], "released DP binary differs from image")
        elif service == "stargate-control":
            verify_control_archive(retained / "stargate-control.tar", payload)
        elif service == "tor":
            require(document(retained / "tor-packages.json") == tor_packages(payload),
                    "Tor package report differs from retained image")
    arm = regular(retained / "stargate-proxy-linux-arm64", MAX_PAYLOAD_BYTES)
    require(arm and repro["arm64"] == {"tier": "cross-build-only-no-runtime-acceptance", "sha256": sha(arm)},
            "arm64 cross-build record differs")
    sources = extension_sources(ROOT / "extension")
    zip_path = retained / "stargate-extension.zip"
    check_extension_zip(zip_path, sources)
    require(repro["extension"] == {"tier": "pinned-two-run-byte-identity", "sha256": file_hash(zip_path)},
            "extension reproducibility record differs")
    extension = document(retained / "stargate-extension.zip.inputs.json")
    fields(extension, ("schema", "environment", "recipe_sha256", "helper_image_id", "source_files",
                       "output_sha256"), "extension inputs")
    require(type(extension["schema"]) is int and extension["schema"] == 1 and
            extension["environment"] == pins()["extension"] and
            extension["recipe_sha256"] == sha(regular(ROOT / "scripts/release/extension.Dockerfile")) and
            isinstance(extension["helper_image_id"], str) and
            re.fullmatch(r"sha256:[0-9a-f]{64}", extension["helper_image_id"]) and
            extension["source_files"] == {p: sha(data) for p, data in sources.items()} and
            extension["output_sha256"] == file_hash(zip_path), "extension input/output record differs")
    return candidate


def candidate_pack(args, directory):
    workflow_identity(args.source, args.version)
    source_files = source_identity(args.source, args.version)
    require_remote_tag(args.source, args.version)
    reject_existing_version(args.version)
    policy = protection()
    metadata = retained_metadata(args)
    archive = directory / "artifact.zip"
    require_space(directory, metadata["size_in_bytes"])
    download(API + "/actions/artifacts/" + str(args.artifact_id) + "/zip", archive, MAX_ARCHIVE,
             token=os.environ["GITHUB_TOKEN"])
    require(archive.stat().st_size == metadata["size_in_bytes"], "retained archive length differs")
    retained = directory / "retained"
    extract_artifact(archive, metadata["digest"][7:], retained)
    archive.unlink()
    candidate_path = retained / "candidate.json"
    candidate = validate_retained_candidate(retained, args.source, args.version, source_files)
    require(candidate["prepare_run_id"] == args.prepare_run_id and candidate["prepare_run_attempt"] == args.prepare_run_attempt,
            "retained candidate run differs")
    evidence = directory / "evidence"
    fetch_evidence(args.evidence_commit, args.version, evidence)
    evidence_hash = check_evidence(candidate_path, evidence)
    pack = {"schema": 1, "source": args.source, "version": args.version, "evidence_commit": args.evidence_commit,
            "artifact_id": args.artifact_id, "prepare_run_id": args.prepare_run_id, "prepare_run_attempt": args.prepare_run_attempt,
            "candidate_sha256": file_hash(candidate_path), "archive": metadata, "evidence_sha256": evidence_hash,
            "protection": policy, "inputs_sha256": file_hash(ROOT / "scripts/release/inputs.json")}
    return pack, retained, evidence


def signature_flags(source, tag):
    return ["--trusted-root", tool("trusted-root"), "--certificate-identity", "https://github.com/" + REPOSITORY
            + "/.github/workflows/release.yml@refs/tags/" + tag,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--certificate-github-workflow-repository", REPOSITORY,
            "--certificate-github-workflow-ref", "refs/tags/" + tag,
            "--certificate-github-workflow-sha", source,
            "--certificate-github-workflow-trigger", "workflow_dispatch"]


def archive_directory(directory, output):
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as tf:
        for path in sorted(Path(directory).rglob("*")):
            require(not path.is_symlink(), "archive input contains symlink")
            if path.is_dir():
                continue
            require(stat.S_ISREG(path.lstat().st_mode), "archive input contains special file")
            member = tarfile.TarInfo(path.relative_to(directory).as_posix())
            member.size = path.stat().st_size
            member.mode, member.mtime = 0o644, 0
            with path.open("rb") as stream:
                tf.addfile(member, stream)


def upload_asset(release_id, path):
    require(type(release_id) is int and release_id > 0, "invalid release ID")
    require(path.stat().st_size <= 2 * 1024**3, "release asset exceeds GitHub size limit")
    url = "https://uploads.github.com/repos/" + REPOSITORY + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(path.name, safe="")
    # urllib streams a file object with the declared Content-Length; neither a
    # token in argv nor an unbounded in-memory OCI archive is needed.
    with path.open("rb") as data:
        request = urllib.request.Request(url, data=data, method="POST", headers={
            "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"], "Content-Type": "application/octet-stream",
            "Content-Length": str(path.stat().st_size), "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(request, timeout=60) as response:
            result = decode(response.read(MAX_JSON + 1))
    require(result.get("state") == "uploaded" and result.get("size") == path.stat().st_size
            and result.get("digest") == "sha256:" + file_hash(path), "uploaded release asset identity differs")


def promote(args):
    workflow_identity(args.source, args.version)
    require(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN") and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"),
            "promotion requires separate GitHub OIDC authority")
    with tempfile.TemporaryDirectory(prefix="stargate-promotion-") as temporary:
        directory = Path(temporary)
        pack, retained, evidence = candidate_pack(args, directory)
        require(sha(canonical(pack)) == digest(args.pack_sha256), "protected job reconstructed a different approval pack")
        require(protection(pack, approved=True) == pack["protection"], "protected environment policy changed after pack review")
        require_remote_tag(args.source, args.version)
        reject_existing_draft_or_release(args.source, args.version)
        cosign, crane = tool("cosign"), tool("crane")
        candidate = document(retained / "candidate.json")
        publication = directory / "publication"
        publication.mkdir()
        docker_config = directory / "credentials"
        docker_config.mkdir(mode=0o700)
        auth = base64.b64encode((os.environ["GITHUB_ACTOR"] + ":" + os.environ["GITHUB_TOKEN"]).encode()).decode()
        write_json(docker_config / "config.json", {"auths": {"ghcr.io": {"auth": auth}}})
        (docker_config / "config.json").chmod(0o600)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("COSIGN_", "SIGSTORE_", "DOCKER_"))}
        env["DOCKER_CONFIG"] = str(docker_config)
        signing_config = directory / "signing-config.json"
        write_json(signing_config, checked_signing_config())
        signing_config.chmod(0o600)
        signing = ["--yes", "--signing-config", signing_config, "--oidc-provider", "github-actions",
                   "--trusted-root", tool("trusted-root")]
        verification = signature_flags(args.source, args.version)
        for service in SERVICES:
            reference = candidate["images"][service]
            # crane's default follows the sole layout descriptor, including
            # the inner attestation index; --index would publish a different
            # outer layout object (selected crane source, T081 grounding).
            run([crane, "push", retained / "oci" / service, reference], env=env)
            require(run([crane, "digest", reference], env=env).decode().strip() == reference.split("@")[1],
                    "registry did not preserve retained OCI digest")
            bundle = publication / (service + ".sigstore.json")
            run([cosign, "sign", *signing, "--bundle", bundle, reference], env=env)
            run([cosign, "verify", *verification, reference], env=env)
            size = sum(p.stat().st_size for p in (retained / "oci" / service).rglob("*") if p.is_file())
            count = sum(1 for p in (retained / "oci" / service).rglob("*") if p.is_file())
            require_space(publication, size + count * 2048 + 10240)
            archive_directory(retained / "oci" / service, publication / ("oci-" + service + ".tar"))
            shutil.rmtree(retained / "oci" / service)
        for name in ("compose.json", "candidate.json", "stargate-proxy-linux-amd64", "stargate-proxy-linux-arm64",
                     "stargate-control.tar", "stargate-extension.zip", "stargate-extension.zip.inputs.json",
                     "source.tar", "verify.log", "reproducibility.json", "tor-packages.json"):
            shutil.move(retained / name, publication / name)
        archive_directory(retained / "logs", publication / "build-logs.tar")
        archive_directory(evidence, publication / "evidence.tar")
        write_json(publication / "approval-pack.json", pack)
        manifest = {"schema": 1, "version": args.version, "source": args.source, "platform": "linux/amd64",
                    "images": candidate["images"], "compose_sha256": file_hash(publication / "compose.json"),
                    "source_files": candidate["source_files"], "artifacts": inventory(publication),
                    "pack_sha256": args.pack_sha256}
        manifest_path = publication / "release.json"
        write_json(manifest_path, manifest)
        bundle = publication / "release.sigstore.json"
        run([cosign, "sign-blob", *signing, "--bundle", bundle, manifest_path], env=env)
        run([cosign, "verify-blob", "--bundle", bundle, *verification, manifest_path], env=env)
        # A failed upload may leave immutable GHCR objects or an unpublished
        # draft. Only this final verified manifest/release advances install.
        fresh_trust()
        require(protection(pack, approved=True) == pack["protection"], "approval policy changed during publication")
        require_remote_tag(args.source, args.version)
        reject_existing_draft_or_release(args.source, args.version)
        release = api("/releases", method="POST", expected_status=201,
                      data={"tag_name": args.version, "target_commitish": args.source,
                      "name": "Stargate " + args.version, "draft": True, "prerelease": False,
                      "body": "Source " + args.source + ". Approval pack SHA256 " + args.pack_sha256
                      + ". Verify release.json and its Sigstore bundle before installation; see docs/releasing.md at that source."})
        require(type(release) is dict and type(release.get("id")) is int and release["id"] > 0 and
                release.get("tag_name") == args.version and release.get("draft") is True,
                "release staging did not return the owned target draft")
        for path in sorted(publication.iterdir()):
            upload_asset(release["id"], path)
        require_remote_tag(args.source, args.version)
        published = api("/releases/" + str(release["id"]), method="PATCH", expected_status=200,
                        data={"draft": False, "make_latest": "false"})
        require(type(published) is dict and published.get("id") == release["id"] and
                published.get("tag_name") == args.version and published.get("draft") is False,
                "release publication returned an incomplete or conflicting result; reconcile manually")


def promotion_pack(args):
    with tempfile.TemporaryDirectory(prefix="stargate-pack-") as temporary:
        pack, _, _ = candidate_pack(args, Path(temporary))
        write_json(args.output, pack)
        checksum = sha(canonical(pack))
        summary = ("Review the complete retained candidate and immutable evidence commit before approving.\n\n"
                   + "Required approval comment:\n\n" + approval_comment(pack) + "\n")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
                stream.write(summary)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                stream.write("pack_sha256=" + checksum + "\n")
        print(summary)


def extension_sources(directory):
    result = {}
    total = 0
    for path in sorted(Path(directory).rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if relative == "dist" or relative.startswith("dist/"):
            continue
        require(not path.is_symlink(), "extension source contains a symlink")
        if path.is_dir():
            continue
        require(re.fullmatch(r"[A-Za-z0-9._/-]+", relative), "unsupported extension filename")
        data = regular(path, MAX_JSON)
        total += len(data)
        require(total <= 32 * 1024**2, "extension source exceeds bound")
        result[relative] = data
    require("package.sh" in result and "manifest.json" in result, "extension source is incomplete")
    return result


def check_extension_zip(path, sources):
    expected = {name: data for name, data in sources.items()
                if PurePosixPath(name).name not in ("package.sh", ".keep")}
    require(Path(path).stat().st_size <= 64 * 1024**2, "extension archive exceeds bound")
    with zipfile.ZipFile(path) as z:
        require(z.namelist() == sorted(expected), "extension archive member set/order differs")
        for info in z.infolist():
            require(info.create_system == 3 and info.external_attr >> 16 == 0o100644 and not info.extra
                    and info.date_time == (1980, 1, 1, 0, 0, 0), "extension archive metadata is not canonical")
            require(info.file_size == len(expected[info.filename]) and z.read(info) == expected[info.filename],
                    "extension archive source bytes differ")


def package_extension(args):
    sources = extension_sources(ROOT / "extension")
    require(extension_sources(args.source_dir) == sources, "packaging source differs from reviewed extension")
    require(not args.output.exists() and not Path(str(args.output) + ".inputs.json").exists(), "packaging output already exists")
    inputs = pins()["extension"]
    recipe = ROOT / "scripts/release/extension.Dockerfile"
    recipe_data = regular(recipe)
    require(inputs["platform"] == "linux/amd64" and inputs["base"].encode() in recipe_data
            and inputs["inrelease_sha256"].encode() in recipe_data, "archive recipe differs from selected environment")
    for name, record in inputs["packages"].items():
        require((name + "=" + record["version"]).encode() in recipe_data and record["package_sha256"].encode() in recipe_data
                and record["file_sha256"].encode() in recipe_data, "archive recipe package pin differs")
    buildx = tool("docker-buildx")
    require_space(args.output.parent, sum(map(len, sources.values())) * 3)
    with tempfile.TemporaryDirectory(prefix="stargate-zip-") as temporary:
        directory = Path(temporary)
        snapshot = directory / "source"
        snapshot.mkdir()
        for name, data in sources.items():
            path = snapshot / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        tag = "stargate-release-zip:" + sha(str(directory).encode())[:24]
        metadata = directory / "build.json"
        try:
            run([buildx, "build", "--no-cache", "--platform", "linux/amd64", "--file", recipe,
                 "--load", "--tag", tag, "--metadata-file", metadata, "."], timeout=1200)
            image_id = document(metadata).get("containerimage.config.digest", "")
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "archive helper image identity missing")
            require(run(["docker", "image", "inspect", "--format", "{{.Id}}", tag]).decode().strip() == image_id,
                    "loaded archive helper differs from build")
            hardened = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                        "--security-opt", "no-new-privileges", "--user", str(os.getuid()) + ":" + str(os.getgid())]
            files = [record["file"] for record in inputs["packages"].values()]
            tool_rows = run([*hardened, image_id, "sha256sum", *files]).decode().splitlines()
            require(tool_rows == [record["file_sha256"] + "  " + record["file"] for record in inputs["packages"].values()],
                    "archive tool/library bytes differ")
            run([*hardened, "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                 "--mount", "type=bind,src=" + str(snapshot) + ",dst=/source", image_id, "bash", "/source/package.sh"], timeout=120)
            output = snapshot / "dist/stargate-extension.zip"
            check_extension_zip(output, sources)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(output, args.output)
            write_json(Path(str(args.output) + ".inputs.json"), {"schema": 1, "environment": inputs,
                       "recipe_sha256": sha(recipe_data), "helper_image_id": image_id,
                       "source_files": {name: sha(data) for name, data in sources.items()},
                       "output_sha256": file_hash(args.output)})
        finally:
            # Remove only the tag this invocation assigned, never all tags of
            # a potentially shared content ID or host-global image/cache state.
            primary_failure = sys.exc_info()[0] is not None
            try:
                run(["docker", "image", "rm", tag])
            except (Refusal, OSError):
                # A failed build need not have created its tag. Preserve its
                # diagnostic; a cleanup failure after success is still fatal.
                if not primary_failure:
                    raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("compose")
    p.add_argument("--images", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("verify-install")
    p.add_argument("--release-dir", type=Path, required=True)
    p.add_argument("--output", type=Path)
    p = commands.add_parser("check-evidence")
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--evidence-dir", type=Path, required=True)
    p = commands.add_parser("check-policy")
    p.add_argument("--pack", type=Path, required=True)
    p.add_argument("--approved", action="store_true")
    p = commands.add_parser("extract-artifact")
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("install-tools")
    p.add_argument("--purpose", choices=("prepare", "validate", "promote", "install"), required=True)
    p = commands.add_parser("check-verify")
    p.add_argument("--log", type=Path, required=True)
    p = commands.add_parser("inspect-oci")
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--source", required=True)
    p = commands.add_parser("prepare")
    p.add_argument("--source", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("package-extension")
    p.add_argument("--source-dir", type=Path, default=ROOT / "extension")
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("check-retained")
    p.add_argument("--source", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--artifact-id", type=int, required=True)
    p.add_argument("--prepare-run-id", type=int, required=True)
    p.add_argument("--prepare-run-attempt", type=int, required=True)
    p = commands.add_parser("verify-candidate")
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--version", required=True)
    for name in ("promotion-pack", "promote"):
        p = commands.add_parser(name)
        p.add_argument("--source", required=True)
        p.add_argument("--version", required=True)
        p.add_argument("--evidence-commit", required=True)
        p.add_argument("--artifact-id", type=int, required=True)
        p.add_argument("--prepare-run-id", type=int, required=True)
        p.add_argument("--prepare-run-attempt", type=int, required=True)
        if name == "promotion-pack":
            p.add_argument("--output", type=Path, required=True)
        else:
            p.add_argument("--pack-sha256", required=True)
    args = parser.parse_args()
    if args.command == "compose":
        write_json(args.output, compose(document(args.images)))
    elif args.command == "verify-install":
        print(verify_install(args.release_dir, args.output))
    elif args.command == "check-evidence":
        print(check_evidence(args.candidate, args.evidence_dir))
    elif args.command == "check-policy":
        print(canonical(protection(document(args.pack), args.approved)).decode(), end="")
    elif args.command == "extract-artifact":
        extract_artifact(args.archive, args.sha256, args.output)
    elif args.command == "install-tools":
        install_tools(args.purpose)
    elif args.command == "check-verify":
        print(canonical(check_verify(args.log)).decode(), end="")
    elif args.command == "inspect-oci":
        print(canonical(inspect_oci(args.directory, args.source)).decode(), end="")
    elif args.command == "prepare":
        prepare(args)
    elif args.command == "package-extension":
        package_extension(args)
    elif args.command == "check-retained":
        print(canonical(retained_metadata(args)).decode(), end="")
    elif args.command == "verify-candidate":
        print(canonical(validate_retained_candidate(args.directory, args.source, args.version,
                                                   source_identity(args.source, args.version))).decode(), end="")
    elif args.command == "promotion-pack":
        promotion_pack(args)
    elif args.command == "promote":
        promote(args)


if __name__ == "__main__":
    try:
        main()
    except (Refusal, OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        print("release: refusing: " + str(error), file=sys.stderr)
        sys.exit(1)
