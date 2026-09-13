"""Run one admitted, bounded Windows Slice managed-validation action on Linux.

The accepted protocol and independent source/provenance review authorize execution.
This helper records consumption and enforces the mechanical execution boundaries.
It is not a hostile-code sandbox or a replacement for contextual admission review.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


REPOSITORY = Path(__file__).resolve().parents[2]
ROOT = Path("/var/tmp/azureauth-windows-slice-108")
PROTOCOL = "docs/research/experiments/windows-slice-validation.md"
RUNNERS = ("tools/validation/run_managed.py", "tools/validation/fetch_packages.py")
GRANT = "a0f741b59e09f1eb95594dbfde7a6e634d962210"
WAVE_BLOB = "8bbc98cc2e892a33c06d190983d9c0a09a8d6282"
PROJECT = "tests/Authentication.Scenarios/Authentication.Scenarios.csproj"
ASSEMBLY = "tests/Authentication.Scenarios/bin/Release/net10.0/Authentication.Scenarios.dll"
SDK_HASHES = {
    "dotnet": "01d89e0a0191052bfea616cd4ce624c8faf13b05bbddf7f64499c23e2a9d9269",
    "sdk/10.0.401/dotnet.dll": "bf8844d3d50869c1c05ff4aaf1908a81ca657106bed52be1388a8323690f5049",
    "sdk/10.0.401/MSBuild.dll": "c00b1a9d5e458b2775ee1ea353cd8735ee5e5bf137e7c8c7a468ffa6c90c4ab4",
    "shared/Microsoft.NETCore.App/10.0.12/System.Private.CoreLib.dll":
        "26304a2985357b9ee277f273667fcd9c892edae3ee6eba76f739033e95eb39b3",
}

# Exact reviewed disposition in the protocol's "Action 0022 Build Disposition".
# This does not change the failed receipt or admit another source or execution.
DISPOSED_BUILD_HASHES = {
    "started.json": "5db34bcbc6740c80b58553d56c7aa8779c11cb21ffc115f21568fc2abe88cf4f",
    "inputs.json": "f2f2b439225c90b130c8f662d54e813e604a7c55bbec3498aba02d900151b5a8",
    "result.json": "c02ba234adac677a63147c57fa0fca240846839953743d08c08e2576dd43bba7",
    "output.txt": "b91afcbc9cd5f0437906fdb6a314f34c9b0fe3a3e9cb9d2c6044ab6032958442",
}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def disposed_build_stop(action):
    return action.name == "0022" and all(
        (action / name).is_file() and digest(action / name) == expected
        for name, expected in DISPOSED_BUILD_HASHES.items()
    )


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def git(*arguments, cwd=REPOSITORY):
    # These are local Git operations only. Hooks cannot execute candidate commands.
    return subprocess.check_output(
        ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments],
        cwd=cwd, timeout=30, stderr=subprocess.DEVNULL,
    ).decode().strip()


def group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def execute(command, cwd, environment, ceiling):
    started = time.monotonic()
    cancelled = False

    def cancel(_number, _frame):
        nonlocal cancelled
        cancelled = True

    previous = {number: signal.signal(number, cancel) for number in (signal.SIGINT, signal.SIGTERM)}
    process = None
    output, reason, quiet = bytearray(), None, False
    try:
        process = subprocess.Popen(command, cwd=cwd, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                if cancelled or time.monotonic() - started >= ceiling:
                    reason = "cancelled" if cancelled else "timeout"
                    break
                for key, _mask in selector.select(0.1):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(output) + len(chunk) > 8 * 1024 * 1024:
                        reason = "output-limit"
                        break
                    else:
                        output.extend(chunk)
                if reason:
                    break
        process.poll()  # Reap an exited leader before checking its group.
        if group_exists(process.pid):
            reason = reason or "surviving-owned-process"
            for number in (signal.SIGTERM, signal.SIGKILL):
                if not group_exists(process.pid):
                    break
                os.killpg(process.pid, number)
                until = time.monotonic() + 5
                while time.monotonic() < until and group_exists(process.pid):
                    process.poll()
                    time.sleep(0.05)
        quiet = not group_exists(process.pid)
        return {"exit_code": process.poll(), "termination": reason,
                "quiescent": quiet, "elapsed_seconds": round(time.monotonic() - started, 3)}, bytes(output)
    finally:
        if process is not None and not quiet and group_exists(process.pid):
            # Preserve an incomplete receipt if unexpected controller failure prevents
            # the normal termination/evidence path. Never continue after that state.
            os.killpg(process.pid, signal.SIGKILL)
        if process is not None and process.stdout is not None:
            process.stdout.close()
        for number, handler in previous.items():
            signal.signal(number, handler)


def snapshot(checkout):
    paths = git("ls-files", cwd=checkout).splitlines()
    return {path: digest(checkout / path) for path in paths}


def restore_inputs(checkout, config):
    # Source admission also inspects imports outside these directories. This initial
    # protocol permits only the pinned SDK, reviewed package targets and these roots.
    paths = [checkout / "global.json", config]
    for root_name in ("src", "tests"):
        for current, directories, files in os.walk(checkout / root_name):
            directories[:] = [name for name in directories if name not in ("bin", "obj")]
            paths.extend(Path(current) / name for name in files if not name.endswith(".cs"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def artifact_hashes(checkout):
    return {str(path.relative_to(checkout)): digest(path)
            for name in ("src", "tests") for path in (checkout / name).rglob("*")
            if path.is_file() and ("bin" in path.parts or path.name == "project.assets.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fetch", "restore", "build", "test"))
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--review", required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--package", action="append", default=[])
    parser.add_argument("--expect", choices=("green", "red"), default="green")
    arguments = parser.parse_args()
    os.umask(0o077)
    if platform.system() != "Linux" or platform.machine() != "x86_64" or "microsoft" not in platform.release().lower():
        raise ValueError("This protocol requires the designated WSL2 Linux x64 host")
    for revision in (arguments.protocol, arguments.source, arguments.target):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("Use full immutable commits")
    if not re.fullmatch(r"https://github.com/hcoona/microsoft-authentication-cli/pull/[0-9]+#(?:issuecomment|pullrequestreview)-[0-9]+", arguments.review):
        raise ValueError("A governing independent admission review is required")
    if arguments.expect == "red" and arguments.action != "test":
        raise ValueError("Only an executed assertion failure can be an expected red result")
    if bool(arguments.package) != (arguments.action == "fetch") or len(arguments.package) > 40:
        raise ValueError("Only fetch accepts a bounded exact package list")
    if git("rev-parse", "origin/main-v2") != arguments.target:
        raise ValueError("Refresh and inspect accepted target before execution")
    git("merge-base", "--is-ancestor", arguments.protocol, arguments.target)
    git("merge-base", "--is-ancestor", GRANT, arguments.source)
    if git("rev-parse", f"{arguments.target}:docs/delivery-wave.md") != WAVE_BLOB:
        raise ValueError("The relied-on Wave changed; refresh protocol and gate evidence")
    for path in (PROTOCOL, *RUNNERS):
        if git("hash-object", str(REPOSITORY / path)) != git("rev-parse", f"{arguments.protocol}:{path}"):
            raise ValueError("Protocol/runner bytes differ from the accepted revision")
    sdk = arguments.sdk.resolve(strict=True)
    for path, expected in SDK_HASHES.items():
        if digest(sdk / path) != expected:
            raise ValueError("Installed SDK identity mismatch")

    marker = {"issue": 108, "grant": GRANT, "protocol_family": PROTOCOL}
    if not ROOT.exists() and not ROOT.is_symlink():
        ROOT.mkdir(mode=0o700)
        write_new(ROOT / "owner.json", marker)
        (ROOT / "actions").mkdir()
        (ROOT / "feed").mkdir()
        (ROOT / "packages").mkdir()
    status = ROOT.lstat()
    if ROOT.is_symlink() or status.st_uid != os.getuid() or status.st_mode & 0o777 != 0o700:
        raise ValueError("Unexpected experiment root ownership")
    if json.loads((ROOT / "owner.json").read_text()) != marker:
        raise ValueError("Unknown experiment history")
    # Lock plus exclusive starts provides sequential, crash-visible accounting.
    with (ROOT / "action.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = sorted((ROOT / "actions").iterdir())
        receipts = []
        for number, action in enumerate(previous, 1):
            if action.name != f"{number:04d}":
                raise ValueError("Noncontiguous action history")
            receipt = json.loads((action / "result.json").read_text())
            prior_start = json.loads((action / "started.json").read_text())
            if not receipt["continuation_allowed"]:
                if not disposed_build_stop(action):
                    raise ValueError("Previous stop requires independently accepted disposition")
                if number == len(previous) and (
                    arguments.action != "build" or arguments.source == prior_start["source"]
                ):
                    raise ValueError("Disposed build stop requires a newly admitted corrected-source build")
            receipts.append(prior_start)
        preparation = arguments.action in ("fetch", "restore")
        if sum(item["action"] in ("fetch", "restore") for item in receipts) + preparation > 12:
            raise ValueError("Initial preparation allocation exhausted")
        if sum(item["action"] in ("build", "test") for item in receipts) + (not preparation) > 80:
            raise ValueError("Initial build/test allocation exhausted")
        if sum(item["reserved_download_bytes"] for item in receipts) + (128 * 1024 * 1024 if arguments.action == "fetch" else 0) > 1024**3:
            raise ValueError("Initial public download allocation exhausted")
        action = ROOT / "actions" / f"{len(previous) + 1:04d}"
        action.mkdir()
        started = {"action": arguments.action, "utc": utc(), "protocol": arguments.protocol,
                   "target": arguments.target, "source": arguments.source,
                   "source_tree": git("rev-parse", arguments.source + "^{tree}"),
                   "review": arguments.review, "expected": arguments.expect,
                   "packages": arguments.package,
                   "reserved_download_bytes": 128 * 1024 * 1024 if arguments.action == "fetch" else 0}
        write_new(action / "started.json", started)
        result = {"continuation_allowed": False, "utc": None, "status": "controller-failed"}
        try:
            checkout = ROOT / "subject"
            if not checkout.exists():
                git("worktree", "add", "--detach", str(checkout), arguments.source)
            else:
                git("diff", "--exit-code", "HEAD", cwd=checkout)
                # Retain generated lockfiles before a later source commit adopts them.
                for path in git("ls-files", "--others", "--exclude-standard", cwd=checkout).splitlines():
                    if Path(path).name != "packages.lock.json" or not path.startswith(("src/", "tests/")):
                        raise ValueError("Unreviewed file in execution checkout")
                    if path in git("ls-tree", "-r", "--name-only", arguments.source).splitlines():
                        if git("hash-object", str(checkout / path)) != git("rev-parse", f"{arguments.source}:{path}"):
                            raise ValueError("Candidate lock differs from the retained resolution")
                        saved = action / "retained-locks" / path
                        saved.parent.mkdir(parents=True, exist_ok=True)
                        (checkout / path).rename(saved)
                git("checkout", "--detach", arguments.source, cwd=checkout)
            before = snapshot(checkout)
            for name in ("home", "temp", "results", "downloads"):
                (action / name).mkdir()
            config = ROOT / "nuget.config"
            if not config.exists():
                config.write_text('<configuration><packageSources><clear/><add key="owned" value="'
                                  + str(ROOT / "feed") + '"/></packageSources>'
                                  '<packageSourceMapping><clear/><packageSource key="owned">'
                                  '<package pattern="*"/></packageSource></packageSourceMapping>'
                                  '</configuration>\n', encoding="utf-8")
            environment = {
                "PATH": f"{sdk}:/usr/bin:/bin", "HOME": str(action / "home"),
                "TMPDIR": str(action / "temp"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "DOTNET_ROOT": str(sdk), "DOTNET_CLI_HOME": str(action / "home"),
                "NUGET_PACKAGES": str(ROOT / "packages"),
                "NUGET_HTTP_CACHE_PATH": str(action / "home" / "http"),
                "NUGET_PLUGINS_CACHE_PATH": str(action / "home" / "plugins"),
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "TESTINGPLATFORM_TELEMETRY_OPTOUT": "1",
                "DOTNET_NUGET_SIGNATURE_VERIFICATION": "false",
                "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false",
                "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH": "false", "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true",
                "DOTNET_CLI_USE_MSBUILD_SERVER": "0", "MSBUILDDISABLENODEREUSE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            dotnet = str(sdk / "dotnet")
            if arguments.action == "fetch":
                command = ["/usr/bin/python3", "-I", str(REPOSITORY / RUNNERS[1]),
                           str(action / "downloads"), *arguments.package]
            elif arguments.action == "restore":
                command = [dotnet, "restore", PROJECT, "--configfile", str(config),
                           "--packages", str(ROOT / "packages"), "--disable-parallel", "--verbosity", "minimal",
                           "-p:NuGetAudit=false", "-p:RestorePackagesWithLockFile=true",
                           "-p:UseSharedCompilation=false", "-m:1", "-nr:false"]
                if (checkout / "tests/Authentication.Scenarios/packages.lock.json").exists():
                    command.append("--locked-mode")
            else:
                restore = json.loads((ROOT / "restore.json").read_text())
                if restore["inputs"] != restore_inputs(checkout, config) or restore["assets"] != {
                    path: digest(checkout / path) for path in restore["assets"]
                }:
                    raise ValueError("Restore inputs or generated assets changed")
                if arguments.action == "build":
                    command = [dotnet, "build", PROJECT, "-c", "Release", "--no-restore",
                               "--disable-build-servers", "-m:1", "-nr:false",
                               "-p:UseSharedCompilation=false", "--verbosity", "minimal"]
                else:
                    build = json.loads((ROOT / "build.json").read_text())
                    if build["source"] != arguments.source or build["artifacts"] != artifact_hashes(checkout):
                        raise ValueError("No unchanged successful build for this source")
                    command = [dotnet, ASSEMBLY, "--report-trx", "--results-directory", str(action / "results")]
            write_new(action / "inputs.json", {"command": command, "environment": environment,
                                               "source_hashes": before, "toolchain_hashes": SDK_HASHES})
            outcome, output = execute(command, checkout, environment, 180 if preparation else 120)
            (action / "output.txt").write_bytes(output)
            result.update(outcome)
            expected_exit = 2 if arguments.expect == "red" else 0
            passed = outcome["quiescent"] and outcome["termination"] is None and outcome["exit_code"] == expected_exit
            if snapshot(checkout) != before:
                raise ValueError("Tracked source changed during execution")
            if arguments.action == "test" and passed:
                files = list((action / "results").glob("*.trx"))
                if len(files) != 1:
                    raise ValueError("Missing or ambiguous TRX evidence")
                counters = ET.parse(files[0]).find(".//{*}Counters")
                if counters is None or int(counters.attrib["executed"]) == 0:
                    raise ValueError("No executed business tests")
                failed = int(counters.attrib["failed"])
                passed = (failed > 0) if arguments.expect == "red" else (failed == 0)
                result["tests"] = counters.attrib
            if arguments.action == "fetch" and passed:
                for package in (action / "downloads").glob("*.nupkg"):
                    target = ROOT / "feed" / package.name
                    if target.exists():
                        raise ValueError("A package identity was already fetched")
                    os.link(package, target)
            if arguments.action == "restore" and passed:
                restored = {"inputs": restore_inputs(checkout, config), "assets": {
                    str(path.relative_to(checkout)): digest(path)
                    for name in ("src", "tests") for path in (checkout / name).rglob("*")
                    if path.is_file() and "obj" in path.parts and path.suffix in (".json", ".props", ".targets")}}
                write_new(action / "restore.json", restored)
                (ROOT / "restore.json").write_text(json.dumps(restored), encoding="utf-8")
            if arguments.action == "build" and passed:
                built = {"source": arguments.source, "artifacts": artifact_hashes(checkout)}
                write_new(action / "build.json", built)
                (ROOT / "build.json").write_text(json.dumps(built), encoding="utf-8")
            result.update(status="expected-result" if passed else "unexpected-result", continuation_allowed=passed)
        except Exception as error:
            result["error_type"] = type(error).__name__
        finally:
            result["utc"] = utc()
            write_new(action / "result.json", result)
        print(json.dumps({"action": action.name, **result}))
        return 0 if result["continuation_allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
