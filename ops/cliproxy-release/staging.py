"""Run one forward-and-restart-rollback rehearsal on a disposable Docker gateway."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

DIGEST = r"[0-9a-f]{64}"
VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
MAX_BYTES = 768 * 1024 * 1024
ARCHIVES = {"baseline": "baseline.oci.tar.zst", "candidate": "candidate.oci.tar.zst"}
CONFIG = b"""host: "127.0.0.1"
port: 19237
auth-dir: /state/auths
api-keys: [staging-client]
request-retry: 0
remote-management:
  disable-control-panel: true
plugins:
  enabled: true
  dir: /plugins
  configs:
    cloudflare-workers-ai: {enabled: true}
    hopper: {enabled: true}
    meta:
      enabled: true
      reasoning-replay:
        enabled: true
        models: [muse-spark-1.3-contributor]
    nvidia-nim: {enabled: true}
    openrouter: {enabled: true}
    synthetic: {enabled: true}
    opencode-go: {enabled: false}
    subscription-pool: {enabled: false}
    zai-coding-plan: {enabled: false}
"""


class StagingError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def download(root):
    url = os.environ.pop("BUNDLE_URL", "")
    expected = os.environ["BUNDLE_SHA256"]
    destination = root / "bundle.zip"
    target = urllib.parse.urlsplit(url)
    if not (re.fullmatch(DIGEST, expected) and target.scheme == "https" and target.hostname
            and not target.username and not target.password and not target.fragment):
        raise StagingError("missing or invalid staging bundle binding")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    digest = hashlib.sha256()
    size = 0
    with opener.open(url, timeout=30) as response, destination.open("xb") as output:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BYTES:
                raise StagingError("staging bundle exceeds size limit")
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != expected:
        raise StagingError("staging bundle digest mismatch")
    return destination


def unique_keys(pairs):
    result = dict(pairs)
    if len(pairs) != len(result):
        raise StagingError("duplicate JSON key")
    return result


def unpack(bundle, root, *, preloaded):
    """Extract only exact OCI archive and flat library paths into a fresh directory."""
    if bundle.stat().st_size > MAX_BYTES:
        raise StagingError("staging bundle exceeds size limit")
    with zipfile.ZipFile(bundle) as archive:
        files = archive.infolist()
        names = {entry.filename for entry in files}
        if len(files) != len(names) or len(files) > 67 or sum(f.file_size for f in files) > MAX_BYTES:
            raise StagingError("invalid staging bundle size or duplicate path")
        allowed = r"(?:baseline|candidate)/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}\.so"
        if any(entry.is_dir() or (entry.filename not in {"release.json", *ARCHIVES.values()}
                                  and not re.fullmatch(allowed, entry.filename)) for entry in files):
            raise StagingError("unexpected staging bundle member")
        if "release.json" not in names or archive.getinfo("release.json").file_size > 4096:
            raise StagingError("invalid staging manifest size")
        release = json.loads(archive.read("release.json"), object_pairs_hook=unique_keys)
        if type(release) is not dict or release.keys() != ARCHIVES.keys():
            raise StagingError("invalid staging manifest")
        for phase, spec in release.items():
            formats = {"image": "sha256:" + DIGEST, "docker_config": "sha256:" + DIGEST,
                       "executable": DIGEST, "meta": VERSION}
            if (type(spec) is not dict or spec.keys() != formats.keys()
                    or any(type(spec[k]) is not str or not re.fullmatch(pattern, spec[k])
                           for k, pattern in formats.items())):
                raise StagingError("invalid staged artifact identity")
            meta = [name for name in names if name.startswith(f"{phase}/meta-")]
            if meta != [f"{phase}/meta-v{spec['meta']}.so"]:
                raise StagingError("missing or ambiguous Meta library")
        required = {ARCHIVES["baseline"]}
        if release["candidate"]["image"] != release["baseline"]["image"]:
            required.add(ARCHIVES["candidate"])
        if (names & set(ARCHIVES.values())) != (set() if preloaded else required):
            raise StagingError("staging image archive set mismatch")
        if all(release["candidate"][key] == release["baseline"][key] for key in ("image", "meta")):
            raise StagingError("candidate and baseline have identical identities")
        for entry in files:
            if entry.filename != "release.json":
                dest = root / entry.filename
                dest.parent.mkdir(exist_ok=True)
                with archive.open(entry) as source, dest.open("xb") as output:
                    shutil.copyfileobj(source, output)
    return release


def command(*argv, timeout=30, combine=False):
    if argv[0] == "docker":
        argv = ("docker", "--host", "unix:///var/run/docker.sock", *argv[1:])
    result = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout)
    return (result.stdout + result.stderr if combine else result.stdout).strip()


class Gateway:
    def __init__(self, root):
        self.root = root
        self.container = None
        self.state = root / "state"
        self.state.mkdir()
        auths = self.state / "auths"
        auths.mkdir()
        self.auth = auths / "meta.json"
        self.auth.write_text(json.dumps({
            "type": "meta-muse", "auth_kind": "oauth", "email": "fixture@example.invalid",
            "disabled": False, "access_token": "staging-meta",
            "base_url": "http://127.0.0.1:19238/meta",
        }))
        self.auth_bytes = self.auth.read_bytes()
        self.config = root / "config.yaml"
        self.uid = os.getuid()
        self.gid = os.getgid()

    def stop(self):
        if self.container:
            command("docker", "container", "rm", "--force", "--volumes", self.container)
            self.container = None

    def switch(self, phase, spec, config):
        self.stop()
        # Rollback remounts the original libraries and replaces only the
        # synthetic config. Auth and plugin state use the same directory.
        self.config.write_bytes(config)
        name = "cliproxy-staging-" + self.root.name
        image = spec["image"]
        # Docker's classic image store identifies the same rootfs by image config digest.
        if command("docker", "info", "--format", "{{.Driver}}") == "overlay2":
            image = spec["docker_config"]
        identity = command("docker", "image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}", image)
        if identity != f"{image} linux/amd64":
            raise StagingError("staged image identity mismatch")
        self.container = command(
            "docker", "container", "create", "--name", name, "--pull=never",
            "--network", "none", "--read-only", "--tmpfs", "/tmp:size=512m,exec,nosuid,nodev",
            "--cpus", "2", "--memory", "1g", "--pids-limit", "128",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--log-driver", "json-file", "--log-opt", "max-size=2m", "--log-opt", "max-file=1",
            "--user", f"{self.uid}:{self.gid}", "--env", "HOME=/state",
            "--mount", f"type=bind,src={self.state},dst=/state",
            "--mount", f"type=bind,src={self.config},dst=/CLIProxyAPI/config.yaml",
            "--mount", f"type=bind,src={self.root / phase},dst=/plugins/linux/amd64,readonly",
            "--entrypoint", "/CLIProxyAPI/CLIProxyAPI", image,
            "-local-model", "-config", "/CLIProxyAPI/config.yaml",
        )
        command("docker", "container", "start", self.container)
        netns = command("docker", "container", "inspect", "--format", "{{.NetworkSettings.SandboxKey}}", self.container)
        if not re.fullmatch(r"/(?:var/)?run/docker/netns/[0-9a-f]+", netns):
            raise StagingError("isolated gateway network namespace unavailable")
        command("sudo", "-n", "nsenter", f"--net={netns}",
                "--setuid", str(self.uid), "--setgid", str(self.gid), "--",
                "/usr/bin/python3", "-IB", str(Path(__file__).resolve().with_name("staging_probe.py")), timeout=25)
        executable = command("docker", "exec", self.container, "sha256sum", "/proc/1/exe").split()[0]
        logs = command("docker", "container", "logs", self.container, combine=True)
        meta = re.findall(r"pluginhost: plugin registered plugin_id=meta .*? version=([^ ]+)", logs)
        if executable != spec["executable"] or meta != [spec["meta"]] or self.auth.read_bytes() != self.auth_bytes:
            raise StagingError("gateway readback mismatch")
        print(f"{phase}: gateway ready, expected Meta registered, stream completed", flush=True)


def rehearse(gateway, release):
    try:
        gateway.switch("baseline", release["baseline"], CONFIG)
        snapshot = gateway.config.read_bytes()
        try:
            gateway.switch("candidate", release["candidate"], snapshot)
        finally:
            gateway.switch("baseline", release["baseline"], snapshot)
            if gateway.config.read_bytes() != snapshot:
                raise StagingError("rollback config readback mismatch")
            print("restart rollback verified", flush=True)
    finally:
        gateway.stop()


def main():
    args = sys.argv[1:]
    preloaded = len(args) == 2 and args[0] == "--preloaded"
    if args and not preloaded:
        raise StagingError("usage: staging.py [--preloaded BUNDLE]")
    with tempfile.TemporaryDirectory(prefix="cliproxy-stage-") as temp:
        root = Path(temp)
        bundle = Path(args[1]) if preloaded else download(root)
        release = unpack(bundle, root, preloaded=preloaded)
        for image in sorted(root.glob("*.oci.tar.zst")):
            command("docker", "image", "load", "--quiet", "--input", str(image), timeout=180)
        rehearse(Gateway(root), release)


if __name__ == "__main__":
    try:
        main()
    except StagingError as error:
        sys.exit(str(error))
    except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile, subprocess.SubprocessError,
            http.client.HTTPException):
        sys.exit("staging failed during bundle preparation, container operation or smoke test")
