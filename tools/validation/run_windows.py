"""Run one admitted Windows managed-file action under the accepted Slice protocol.

The WSL history survives failed Windows starts. No authentication, publishing,
package download, arbitrary command, or automatic retry is exposed here.
"""

import argparse
import base64
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import unquote


REPOSITORY = Path(__file__).resolve().parents[2]
LINUX = Path("/var/tmp/azureauth-windows-slice-108")
HISTORY = LINUX / "windows-actions"
ROOT = Path("/mnt/c/Temp/azureauth-windows-slice-108")
WINDOWS = "C:\\Temp\\azureauth-windows-slice-108"
NUGET_CONFIG = (
    '<configuration><packageSources><clear/><add key="owned" value="' + WINDOWS +
    '\\empty-feed"/></packageSources><packageSourceMapping><clear/><packageSource key="owned">' +
    '<package pattern="*"/></packageSource></packageSourceMapping>' +
    '<fallbackPackageFolders><clear/></fallbackPackageFolders></configuration>\n'
).encode("utf-8")
PROTOCOL = "docs/research/experiments/windows-slice-validation.md"
WAVE = "8bbc98cc2e892a33c06d190983d9c0a09a8d6282"
GRANT = "a0f741b59e09f1eb95594dbfde7a6e634d962210"
CONTROLLERS = ("run_windows.py", "Invoke-WindowsValidation.ps1",
               "Stop-WindowsValidation.ps1", "WindowsValidationJob.cs")
PROJECT = "tests/Authentication.Windows.Scenarios/Authentication.Windows.Scenarios.csproj"
POWERSHELL = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
DOTNET = "C:\\Program Files\\dotnet\\"
FRAMEWORK = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"
TOOLS = {
    DOTNET + "dotnet.exe": "21a46f1e5235cf4e844b9de5429f0e198b9c97a41f0503a66442f1d639ca3ee6",
    DOTNET + "sdk\\10.0.401\\dotnet.dll": "616dbda77bc20692d615e2a679f31ffff04f693e8d6b3e24779cf8838adb6a85",
    DOTNET + "sdk\\10.0.401\\MSBuild.dll": "22f7b95c5cc1e7287a9d561a0e88719c4d545c5f3892e3e6501051f5abcbe147",
    DOTNET + "sdk\\10.0.401\\dotnet.deps.json": "7cf8fff4144ef3484f052c4a4734a53f4d65023798f11da62f3c45ae4353d8e8",
    DOTNET + "sdk\\10.0.401\\NuGet.Packaging.dll": "634860396d6941beb5b007ff0e467e3817b4582dd8e7a15ab089fa6aec66375c",
    DOTNET + "sdk\\10.0.401\\NuGet.Protocol.dll": "9a0912695ccf83daa3c92e4a456db9226d79ac34deb07a10b98ffc85372dc0e4",
    DOTNET + "sdk\\10.0.401\\NuGet.Commands.dll": "3d1ea1e9fc18469646c2dc6b6639d91e595ce1031ac7ddc6d27cb02d196ea015",
    DOTNET + "sdk\\10.0.401\\NuGet.Common.dll": "537a15963cf134fc30e1314007cb276778309beb7672d4735d32fa8b022536b5",
    DOTNET + "sdk\\10.0.401\\NuGet.Configuration.dll": "b4696a39a890bbefeecb01099eedf990d3e108e7ad7d2d57d8cdf4c296dd06f6",
    DOTNET + "shared\\Microsoft.NETCore.App\\10.0.12\\System.Private.CoreLib.dll":
        "1125acc8106c43fc8bad2d203c4c4485df6182d292846c2fff415c1040c54678",
    FRAMEWORK + "csc.exe": "46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00",
    FRAMEWORK + "csc.exe.config": "2d4610ade011e530d817dd3ba4fc787e5dc0c2297cc520c30a643b8fb13f9093",
    FRAMEWORK + "System.dll": "2b3c17c6208a0b4b6beb94e1a066f99ba06cdb2ea919479e99d47e8c6d96dc71",
    FRAMEWORK + "System.Core.dll": "fd1097aed825d392a5dc8d19384381d4bb2a43498ea1c9d917f5d80c66600e1b",
    FRAMEWORK + "mscorlib.dll": "5bffb20e1217bad314143d7e5c4c809bf9f522e8a0a063c8e7e9b25113de26eb",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe":
        "8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e",
}
# Original public archives; signed-package content hashes remain in retained metadata.
ARCHIVES = {
    "microsoft.applicationinsights.2.23.0.nupkg": (1737910,
        "dd497bfad0c65e54a4f78d2a1644f3d0854d4cd01dd83ba506f8d5d53635e28152c7c13210dd5dd3985780aab146a7620de3ebaead8ef12c6f87088676c2157f"),
    "microsoft.codecoverage.18.0.1.nupkg": (10065448,
        "d1bcebcfebd1e3d13f8ed741c925da2523cfe299709cc1c4daab3225981926e0dd20eb4b505b3022755aee4af1215cf6babe8a25915d4cf5ebdd63177e09c336"),
    "microsoft.diasymreader.2.0.0.nupkg": (93176,
        "8a25467f107348b9a2e4daec472c788b33663c8715726376b65985fbaacd1b5a4468981ea25214aef86450538a695ed03183f2b5580c9927755744a2066fe870"),
    "microsoft.extensions.dependencymodel.8.0.2.nupkg": (262269,
        "42a9e54c51b5f99a1d26ae79ce21accb5218a600b2534632aa2c2a4cdcac5d2942d2976f2c915fe8523ec5e390043607ac6b0a530de9e7cbbad9e1841ecea37e"),
    "microsoft.net.illink.tasks.10.0.12.nupkg": (1536960,
        "a294f93f5a7e086ef4c466af79382add0e4e64a77b319d11b35d31e137b097a6dc3dbbb848ba381749fa4410889ef04ac68475d13d75f97d0cf5d8232847ee73"),
    "microsoft.net.test.sdk.18.0.1.nupkg": (39745,
        "71fa67e085b443e7a6203f1e528712ef17e6c306200ff257e52fb309903697b81c633c59d6fbdf71d64770a92ecc21f880c6c162a719aad067f6e65ad1625152"),
    "microsoft.testing.extensions.codecoverage.18.4.1.nupkg": (15815773,
        "93bdcbff249da8b58a9ab8dde72348e9aa6bad2c8a0112a10232e359b1df0768ce6812796727445660605e4f0bcd0dac01b0067b35c6b396cdfbd76665aac425"),
    "microsoft.testing.extensions.telemetry.2.1.0.nupkg": (861704,
        "e9c46498dd6d4638cc22d6833e86c52a213ca8085b839101227fb8cb9f5bac53d81290e487764a5c31f68d48d58fc4a83bd5c3618e2cc20b051208f3c22a52a6"),
    "microsoft.testing.extensions.trxreport.2.1.0.nupkg": (1092875,
        "062eab0b9e79facff9912f9aeccab00f388f3cd106bc1b081b325f0e58141e2a580510dc80f130b74c440a8ea45b18a07ea4d4d9dca883d6cbe27941ecedfe6f"),
    "microsoft.testing.extensions.trxreport.abstractions.2.1.0.nupkg": (470660,
        "a3ef4ec9a7c51e568950eb3524e7f5394d0dfd66d21b9a84f29038987d7059a800ae8c8f7fd8e8c6d0d3bb5b3181dfd7f0925a4ed0ce6770b143e6d7ccc1a130"),
    "microsoft.testing.extensions.vstestbridge.2.1.0.nupkg": (1051356,
        "038b14a0e116ed870a7909d7182ea6a1afce81c63e847b1ddb4bcfb44455741f1845ace04cd64d2297fdbce35442b1635dcd7b7b2281f8c49341e7061352f719"),
    "microsoft.testing.platform.2.1.0.nupkg": (2511423,
        "cf1e26726ff782e1e31c2e84abfeb204d4c761415c6c656ff3c5007c8ab5195eb9eeb19be2b79aa2d1bd75e3ed81c83fcf1c6e3969c5d87cd214a950822b2e17"),
    "microsoft.testing.platform.msbuild.2.1.0.nupkg": (2375619,
        "88c044d4aed24349c08783be89e47849b2ca792abfc31636c927f6db256c7d5e7e57953e4c43740a09d026dd785fac2582fcbc9787c0f1e64b68cbbcb50c2505"),
    "microsoft.testplatform.objectmodel.18.0.1.nupkg": (1665637,
        "a9929cb12e6637b18cc2da5dfad45f02de039a0f3255bb56926f6219fa98d8634e1b6a96f79347eb37ff16b4cb5d3892eeb07bcea8a158611c4aca4e6922bc4d"),
    "microsoft.testplatform.testhost.18.0.1.nupkg": (3260813,
        "497d459d803ccdc36ffe56d62b71a32e7031f778da966c87c903158be4cd580eb547ac7390b30da42ddfa2d6dfa4385e5c2161c32ff5acaa142f268e39ed2312"),
    "mstest.4.1.0.nupkg": (30590,
        "7357bdc9ee9babafe2d594527ea1b8e8750003189d3aa15c10df8ebb8775a74c3b06a6f6eccd4fdbbc89e42c84ccebe6fc920484f30d9c24dcf47c50464b8c1c"),
    "mstest.analyzers.4.1.0.nupkg": (1668456,
        "42cffc4d7b8b937ab582228621b8f48311d1b81ff2d9718b9723cd837c7913169cb2c454b7737b31b0ed9edd3d7f0d2568dda8085e23fe46515522db7fd2bd38"),
    "mstest.testadapter.4.1.0.nupkg": (3589259,
        "07cb3a83aabd10fdce1392e8c80388c0a6485b59bba002f98e2207d9bee49575be1e26de1feddb0a090445cebc5d81bd25d86d34a1db2d00fb9a9bb86c460d70"),
    "mstest.testframework.4.1.0.nupkg": (3523373,
        "cb67ec089ab734eb36c2120858d768d3f894baf2c8793ef3f75f0d7999af74bea69364551a276b2706b91cbf7c6208513125346dc60082820112b5f811e07710"),
    "newtonsoft.json.13.0.3.nupkg": (2441966,
        "99b252bc77d1c5f5f7b51fd4ea7d5653e9961d7b3061cf9207f8643a9c7cc9965eebc84d6467f2989bb4723b1a244915cc232a78f894e8b748ca882a7c89fb92"),
}
DISPOSED = {
    "started.json": "5db34bcbc6740c80b58553d56c7aa8779c11cb21ffc115f21568fc2abe88cf4f",
    "inputs.json": "f2f2b439225c90b130c8f662d54e813e604a7c55bbec3498aba02d900151b5a8",
    "result.json": "c02ba234adac677a63147c57fa0fca240846839953743d08c08e2576dd43bba7",
    "output.txt": "b91afcbc9cd5f0437906fdb6a314f34c9b0fe3a3e9cb9d2c6044ab6032958442",
}
DISPOSED_WINDOWS_PREPARATION = {
    "started.json": "b5f6e94a9240778dd028610f5c0c76fe9fafcea2aa0f27bf84d19e9839839142",
    "result.json": "437df40a2c76f7e288de3fd5d36beff41f8b0318a85a55d0b2c24a3ab179d43e",
}
DISPOSED_WINDOWS_RESTORE = {
    "started.json": "98d325740fc4c3cf7e34132faadc2494396a069e8da3885eb72ade65c34fef4c",
    "windows-input.json": "e3075e32ca4d0a5dcc0221d6102ec6ced0db89ff0f3a092f8dcb184e76c2a899",
    "result.json": "891a2040d258df4af84deccadce7388092a430416df2f94bf0e7b93f4ec9527a",
}
PREVIOUS_CONTROLLERS = {
    "run_windows.py": "5670156edbc55851435adca4212f07569d540972656c0ff2cb876b366ab7baed",
    "Invoke-WindowsValidation.ps1": "6c577f6638d5fdaa243e92bc0a5c3bc263b70b1b2ed6c847e6ac32a67af1d113",
}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def direct(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("Linked input or output")


def digest(path, algorithm="sha256"):
    direct(path)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate receipt field")
        result[key] = value
    return result


def read(path):
    direct(path)
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Oversized receipt")
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)


def write_new(path, value):
    direct(path)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def git(*arguments, cwd=REPOSITORY):
    # DrvFS executable bits are synthetic; immutable tree and byte checks remain.
    windows_modes = ["-c", "core.filemode=false"] if cwd == ROOT / "subject" else []
    return subprocess.check_output(
        ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
         *windows_modes, *arguments],
        cwd=cwd, timeout=30, stderr=subprocess.DEVNULL,
    ).decode().strip()


def snapshot(checkout):
    return {name: digest(checkout / name) for name in git("ls-files", cwd=checkout).splitlines()}


def files_under(directory):
    result = {}
    for current, directories, files in os.walk(directory):
        direct(Path(current))
        for name in directories:
            direct(Path(current) / name)
        for name in files:
            path = Path(current) / name
            result[str(path.relative_to(ROOT))] = digest(path)
    return result


def graph_inputs():
    subject = ROOT / "subject"
    result = {"subject/global.json": digest(subject / "global.json"), "nuget.config": digest(ROOT / "nuget.config")}
    for base in (subject / "src", subject / "tests"):
        for current, directories, files in os.walk(base):
            directories[:] = [name for name in directories if name not in ("bin", "obj")]
            for name in files:
                if not name.endswith(".cs"):
                    path = Path(current) / name
                    result[str(path.relative_to(ROOT))] = digest(path)
    return result


def generated(kind):
    result = {}
    for base in (ROOT / "subject/src", ROOT / "subject/tests"):
        for path in base.rglob("*"):
            if path.is_file() and (kind == "build" and any(x in path.parts for x in ("bin", "obj")) or
                                  kind == "restore" and path.parent.name == "obj" and
                                  (path.name == "project.assets.json" or path.name.endswith(
                                      (".nuget.g.props", ".nuget.g.targets", ".nuget.dgspec.json")))):
                result[str(path.relative_to(ROOT))] = digest(path)
    return result


def histories():
    linux = []
    for index, action in enumerate(sorted((LINUX / "actions").iterdir()), 1):
        if action.name != f"{index:04d}":
            raise ValueError("Noncontiguous Linux history")
        receipt = read(action / "result.json")
        if action.name == "0022":
            if any(digest(action / name) != expected for name, expected in DISPOSED.items()):
                raise ValueError("Disposed Linux action changed")
        elif receipt.get("continuation_allowed") is not True:
            raise ValueError("Unresolved Linux action")
        linux.append(read(action / "started.json"))
    windows = []
    for index, action in enumerate(sorted(HISTORY.iterdir()), 1):
        if action.name != f"{index:04d}":
            raise ValueError("Noncontiguous Windows history")
        result = read(action / "result.json")
        if action.name == "0002":
            verify_disposed_windows_preparation(action)
        elif action.name == "0003":
            direct(action)
            if {path.name for path in action.iterdir()} != set(DISPOSED_WINDOWS_RESTORE) or any(
                digest(action / name) != expected for name, expected in DISPOSED_WINDOWS_RESTORE.items()
            ):
                raise ValueError("Disposed Windows restore receipt changed")
        elif result.get("continuation_allowed") is not True or result.get("quiescent") is not True:
            raise ValueError("Unresolved Windows action")
        for name, expected in result["evidence"].items():
            if digest(ROOT / "actions" / action.name / name) != expected:
                raise ValueError("Windows evidence changed")
        windows.append((action, read(action / "started.json"), result))
    return linux, windows


def verify_disposed_windows_preparation(action):
    """Recognize only the accepted pre-subject stop, without changing its receipts."""
    direct(action)
    if {path.name for path in action.iterdir()} != set(DISPOSED_WINDOWS_PREPARATION):
        raise ValueError("Disposed Windows reservation changed")
    for name, expected in DISPOSED_WINDOWS_PREPARATION.items():
        if digest(action / name) != expected:
            raise ValueError("Disposed Windows receipt changed")
    failed = ROOT / "actions/0002"
    direct(failed)
    paths = list(failed.rglob("*"))
    if {str(path.relative_to(failed)) for path in paths} != {
        "home", "home/local", "home/roaming", "temp", "results",
    }:
        raise ValueError("Disposed Windows pre-subject boundary changed")
    for path in paths:
        direct(path)
        if not path.is_dir():
            raise ValueError("Disposed Windows directory changed")


def public_archives(protocol):
    lock = json.loads(git("show", f"{protocol}:tests/Authentication.Scenarios/packages.lock.json"))
    archives = {}
    for framework in lock["dependencies"].values():
        for name, entry in framework.items():
            if entry["type"] == "Project":
                continue
            filename = f"{name.lower()}.{entry['resolved']}.nupkg"
            archives[filename] = (LINUX / "feed" / filename,
                                  LINUX / "packages" / name.lower() / entry["resolved"], entry["contentHash"])
    filename = "microsoft.net.illink.tasks.10.0.12.nupkg"
    prior = Path("/mnt/c/Temp/azureauth-native-aot-diagnostics/round-05")
    archives[filename] = (prior / "feed" / filename, prior / "packages/microsoft.net.illink.tasks/10.0.12",
                          "xi+BDjFpW+Sb+MHFHaH6Y/gV9I8BluFwRXc1QyCdoZbIK26eNiBeFuMTe/FMwc33G1wdHCyDg7CVTmb8OdQrMQ==")
    if set(archives) != set(ARCHIVES):
        raise ValueError("The independently reviewed public archive graph changed")
    for filename, (path, cache, content_hash) in archives.items():
        size, expected = ARCHIVES[filename]
        if path.stat().st_size != size or digest(path, "sha512") != expected:
            raise ValueError("Retained public archive changed")
        verify_cache(path, cache, content_hash)
    return archives


def verify_cache(archive, cache, content_hash):
    """Compare all retained payloads and cache metadata without extracting a package."""
    filename = archive.name
    metadata = read(cache / ".nupkg.metadata")
    if set(metadata) != {"version", "contentHash", "source"} or metadata["version"] != 2 or metadata["contentHash"] != content_hash:
        raise ValueError("Unreviewed retained NuGet metadata")
    if metadata["source"] not in ("/var/tmp/azureauth-windows-slice-108/feed",
                                  "C:\\Temp\\azureauth-native-aot-diagnostics\\round-05\\feed"):
        raise ValueError("Unexpected retained public source metadata")
    if digest(cache / filename, "sha512") != ARCHIVES[filename][1] or \
            base64.b64decode((cache / (filename + ".sha512")).read_bytes(), validate=True).hex() != ARCHIVES[filename][1]:
        raise ValueError("Retained cache archive/hash differs")
    expected = {".nupkg.metadata", filename, filename + ".sha512"}
    with zipfile.ZipFile(archive) as package:
        for entry in package.infolist():
            name = unquote(entry.filename)
            if entry.is_dir() or name in ("[Content_Types].xml", "_rels/.rels") or name.startswith("package/services/metadata/core-properties/"):
                continue  # NuGet omits OPC container metadata from its extracted payload.
            if name.endswith(".nuspec"):
                name = name.lower()
            if name.lower() in {x.lower() for x in expected} or name.startswith("/") or ".." in Path(name).parts or \
                    any(x in name for x in '\\:*?"<>|') or any(part.endswith((".", " ")) for part in Path(name).parts):
                raise ValueError("Unexpected cache payload path")
            expected.add(name)
            if digest(cache / name) != hashlib.sha256(package.read(entry)).hexdigest():
                raise ValueError("Retained payload differs from its original public archive")
    actual = {str(path.relative_to(cache)) for path in cache.rglob("*") if path.is_file()}
    if actual != expected:
        raise ValueError("Incomplete or extended retained package cache")
    return {name: digest(cache / name) for name in expected}


def windows_wait(command, seconds, cancel_path=None):
    """Bound this Windows controller wait; loss of the Linux proxy is not cleanup."""
    interrupted = False

    def cancel(_number, _frame):
        nonlocal interrupted
        interrupted = True

    old = {number: signal.signal(number, cancel) for number in (signal.SIGINT, signal.SIGTERM)}
    process = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + seconds
        cancellation_started = None
        while process.poll() is None:
            if interrupted and cancellation_started is None:
                cancellation_started = time.monotonic()
                if cancel_path is not None:
                    cancel_path.touch(exist_ok=False)
                deadline = min(deadline, cancellation_started + 15)
            if time.monotonic() >= deadline:
                return None, True
            time.sleep(0.05)
        return process.returncode, interrupted
    finally:
        if process is not None and process.poll() is None:
            # This ends only the local interop proxy. Emergency Windows cleanup is separate.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        for number, handler in old.items():
            signal.signal(number, handler)


def powershell(*arguments):
    return [str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", *arguments]


def preflight():
    # Read-only, fixed Windows path/owner checks before WSL creates any Windows file.
    command = r"""
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess -or [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { exit 1 }
if ([IO.DriveInfo]::new('C:\').DriveType -ne [IO.DriveType]::Fixed) { exit 1 }
foreach ($path in @('C:\', 'C:\Temp', 'C:\Temp\azureauth-windows-slice-108')) {
    if (-not (Test-Path -LiteralPath $path)) {
        if ($path -ne 'C:\Temp\azureauth-windows-slice-108') { exit 1 }
        continue
    }
    $item = Get-Item -LiteralPath $path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 1 }
    if ($path -eq 'C:\Temp\azureauth-windows-slice-108' -and
        (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { exit 1 }
}
exit 0
"""
    encoded = base64.b64encode(command.encode("utf-16le")).decode()
    code, interrupted = windows_wait(powershell("-EncodedCommand", encoded), 20)
    if code != 0 or interrupted:
        raise ValueError("Windows path preflight failed or interrupted")


def prepare_source(source, action):
    subject = ROOT / "subject"
    if not subject.exists():
        git("worktree", "add", "--detach", str(subject), source)
    else:
        git("diff", "--exit-code", "HEAD", cwd=subject)
        for path in git("ls-files", "--others", "--exclude-standard", cwd=subject).splitlines():
            if Path(path).name != "packages.lock.json" or not path.startswith(("src/", "tests/")):
                raise ValueError("Unreviewed source file")
            if path in git("ls-tree", "-r", "--name-only", source).splitlines():
                if git("hash-object", str(subject / path)) != git("rev-parse", f"{source}:{path}"):
                    raise ValueError("Adopted lock differs from restore")
                saved = action / "retained-locks" / path
                saved.parent.mkdir(parents=True, exist_ok=True)
                (subject / path).rename(saved)
        git("checkout", "--detach", source, cwd=subject)
    before = snapshot(subject)
    for name in before:
        if git("hash-object", str(subject / name)) != git("rev-parse", f"{source}:{name}"):
            raise ValueError("Working source differs from immutable Git bytes")
    return before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("bootstrap", "restore", "build", "test"))
    for name in ("protocol", "source", "target", "review"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--expect", choices=("red", "green"), default="green")
    args = parser.parse_args()
    os.umask(0o077)
    if platform.system() != "Linux" or platform.machine() != "x86_64" or "microsoft" not in platform.release().lower():
        raise ValueError("Requires the designated WSL2 host")
    for revision in (args.protocol, args.source, args.target):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("Use full immutable revisions")
    if not re.fullmatch(r"https://github.com/hcoona/microsoft-authentication-cli/pull/[0-9]+#(?:issuecomment|pullrequestreview)-[0-9]+", args.review):
        raise ValueError("Independent admission review required")
    if args.expect == "red" and args.action != "test":
        raise ValueError("Only test assertions may be expected red")
    if git("rev-parse", "origin/main-v2") != args.target or git("rev-parse", f"{args.target}:docs/delivery-wave.md") != WAVE:
        raise ValueError("Refresh accepted target and authority")
    git("merge-base", "--is-ancestor", args.protocol, args.target)
    git("merge-base", "--is-ancestor", GRANT, args.source)
    for name in (PROTOCOL, "tools/validation/run_managed.py", *("tools/validation/" + name for name in CONTROLLERS)):
        if git("hash-object", str(REPOSITORY / name)) != git("rev-parse", f"{args.protocol}:{name}"):
            raise ValueError("Controller/protocol differs from accepted bytes")
    for path, expected in TOOLS.items():
        if digest(Path("/mnt/c") / path[3:].replace("\\", "/")) != expected:
            raise ValueError("Installed tool identity changed")
    direct(LINUX)
    stat = LINUX.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o777 != 0o700 or read(LINUX / "owner.json") != {
        "issue": 108, "grant": GRANT, "protocol_family": PROTOCOL,
    }:
        raise ValueError("Unrecognized Linux ownership/history")
    # Reuse the Linux action lock: neither loop can execute while the other owns it.
    with (LINUX / "action.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not HISTORY.exists():
            HISTORY.mkdir(mode=0o700)
        linux, previous = histories()
        if previous and previous[-1][0].name in ("0002", "0003") and (
            args.action != "restore" or args.source != previous[-1][1]["source"]
        ):
            raise ValueError("The first continuation must restore the unchanged admitted source")
        preparation = args.action in ("bootstrap", "restore")
        prep = sum(start["action"] in ("bootstrap", "restore") for _, start, _ in previous)
        tests = len(previous) - prep
        if prep + preparation > 4 or tests + (not preparation) > 40:
            raise ValueError("Windows allocation exhausted")
        if sum(item["action"] in ("fetch", "restore") for item in linux) + prep + preparation > 16 or \
                sum(item["action"] in ("build", "test") for item in linux) + tests + (not preparation) > 120:
            raise ValueError("Combined Wave capacity exhausted")
        if args.action == "bootstrap" and previous or args.action != "bootstrap" and not previous:
            raise ValueError("Bootstrap occurs exactly once, before restore/build/test")
        archives = public_archives(args.protocol)
        local = HISTORY / f"{len(previous) + 1:04d}"
        local.mkdir()
        start = {"action": args.action, "utc": utc(), "protocol": args.protocol, "source": args.source,
                 "sourceTree": git("rev-parse", args.source + "^{tree}"), "target": args.target,
                 "review": args.review, "expected": args.expect, "linuxActions": len(linux),
                 "priorWindowsPreparation": prep, "priorWindowsBuildTest": tests}
        write_new(local / "started.json", start)
        result = {"continuation_allowed": False, "quiescent": False, "evidence": {}}
        action = ROOT / "actions" / local.name
        launched = False
        try:
            preflight()
            marker = {"issue": 108, "grant": GRANT, "protocol_family": PROTOCOL}
            if not ROOT.exists():
                if previous:
                    raise ValueError("Windows history root disappeared")
                ROOT.mkdir()
                write_new(ROOT / "owner.json", marker)
                for name in ("actions", "controller", "feed", "empty-feed", "packages"):
                    (ROOT / name).mkdir()
            if read(ROOT / "owner.json") != marker or sorted(path.name for path in (ROOT / "actions").iterdir()) != [p.name for p, _, _ in previous]:
                raise ValueError("Unknown or conflicting Windows root history")
            action.mkdir()
            for name in ("home", "home/roaming", "home/local", "temp", "results", "empty-program-files"):
                (action / name).mkdir()
            migrations = {}
            for name in CONTROLLERS:
                data = (REPOSITORY / "tools/validation" / name).read_bytes()
                path = ROOT / "controller" / name
                direct(path)
                if name in PREVIOUS_CONTROLLERS and len(previous) == 3 and not path.exists():
                    raise ValueError("The pre-migration Windows controller disappeared")
                if path.exists():
                    if name in PREVIOUS_CONTROLLERS and len(previous) == 3:
                        expected_previous = PREVIOUS_CONTROLLERS[name]
                        if digest(path) != expected_previous:
                            raise ValueError("Unexpected pre-migration Windows controller")
                        retained = action / ("retained-" + name)
                        with retained.open("xb") as stream:
                            stream.write(path.read_bytes())
                        if digest(retained) != expected_previous:
                            raise ValueError("Retained controller identity changed")
                        with path.open("wb") as stream:
                            stream.write(data)
                        replacement = hashlib.sha256(data).hexdigest()
                        if digest(path) != replacement:
                            raise ValueError("Corrected controller identity changed")
                        migrations[name] = {
                            "retained": retained.name,
                            "previousSha256": expected_previous,
                            "sha256": replacement,
                        }
                    elif path.read_bytes() != data:
                        raise ValueError("Existing controller changed")
                else:
                    with path.open("xb") as stream:
                        stream.write(data)
            if migrations:
                write_new(action / "controller-migration.json", {
                    "previousProtocol": previous[-1][1]["protocol"],
                    "protocol": args.protocol, "files": migrations,
                })
            for name, (original, retained_cache, content_hash) in archives.items():
                expected = ARCHIVES[name][1]
                path = ROOT / "feed" / name
                if not path.exists():
                    if args.action != "bootstrap":
                        raise ValueError("Public feed lost an input")
                    with path.open("xb") as stream:
                        stream.write(original.read_bytes())
                if digest(path, "sha512") != expected:
                    raise ValueError("Copied archive identity changed")
                admitted_files = verify_cache(original, retained_cache, content_hash)
                cache = ROOT / "packages" / retained_cache.parent.name / retained_cache.name
                if not cache.exists():
                    if args.action != "bootstrap":
                        raise ValueError("A previously admitted package cache is missing")
                    cache.mkdir(parents=True)
                    for relative, expected_file in admitted_files.items():
                        destination = cache / relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with destination.open("xb") as stream:
                            stream.write((retained_cache / relative).read_bytes())
                        if digest(destination) != expected_file:
                            raise ValueError("Copied cache payload changed")
                if verify_cache(original, cache, content_hash) != admitted_files:
                    raise ValueError("Existing cache differs from the admitted retained input")
            if list((ROOT / "empty-feed").iterdir()):
                raise ValueError("The fallback feed must remain empty")
            config = ROOT / "nuget.config"
            if not config.exists():
                if args.action != "bootstrap":
                    raise ValueError("The fixed restore config disappeared")
                with config.open("xb") as stream:
                    stream.write(NUGET_CONFIG)
            if config.read_bytes() != NUGET_CONFIG:
                raise ValueError("Restore config differs from the fixed cache-only boundary")
            before = prepare_source(args.source, action)
            inputs = {"subject/" + name: expected for name, expected in before.items()}
            for base in (ROOT / "controller", ROOT / "feed", ROOT / "packages"):
                inputs.update(files_under(base))
            inputs["nuget.config"] = digest(config)
            if args.action in ("build", "test"):
                restores = [p for p, s, _ in previous if s["action"] == "restore"]
                restored = read(ROOT / "actions" / restores[-1].name / "restore.json")
                if restored["inputs"] != graph_inputs() or restored["assets"] != generated("restore"):
                    raise ValueError("Restore prerequisites changed")
                inputs.update(restored["assets"])
            if args.action == "test":
                builds = [p for p, s, _ in previous if s["action"] == "build"]
                built = read(ROOT / "actions" / builds[-1].name / "build.json")
                if built["source"] != args.source or built["artifacts"] != generated("build"):
                    raise ValueError("Unchanged source-bound build required")
                inputs.update(built["artifacts"])
            start.update(fileSha256=inputs, toolSha256=TOOLS)
            if args.action != "bootstrap":
                bootstrap = read(ROOT / "actions/0001/bootstrap.json")
                start.update(helperPath="actions/0001/WindowsValidationJob.dll", helperSha256=bootstrap["sha256"])
                inputs[start["helperPath"]] = bootstrap["sha256"]
                if bootstrap["sourceSha256"] != digest(ROOT / "controller/WindowsValidationJob.cs"):
                    raise ValueError("Bootstrap source binding changed")
            write_new(action / "started.json", start)
            write_new(local / "windows-input.json", {"sha256": digest(action / "started.json")})
            command = powershell("-File", WINDOWS + "\\controller\\Invoke-WindowsValidation.ps1",
                                 "-ActionName", action.name, "-ReservationSha256", digest(action / "started.json"))
            launched = True
            code, interrupted = windows_wait(command, 230, action / "cancel")
            if code is None:
                raise ValueError("Windows controller wait expired")
            win = read(action / "windows-result.json")
            result["quiescent"] = win.get("quiescent") is True
            if interrupted or code != 0 or win.get("safetyStop") is not False or not result["quiescent"] or \
                    win.get("reservationSha256") != digest(action / "started.json"):
                raise ValueError("Windows action stopped")
            if snapshot(ROOT / "subject") != before:
                raise ValueError("Tracked source changed during execution")
            direct(action / "empty-program-files")
            if not (action / "empty-program-files").is_dir() or list((action / "empty-program-files").iterdir()):
                raise ValueError("Empty program-files directory changed during execution")
            for name, expected in inputs.items():
                if args.action != "test" and "obj" in Path(name).parts:
                    continue  # Restore/build may replace their generated metadata.
                if digest(ROOT / name) != expected:
                    raise ValueError("Protected execution input changed")
            for name, expected in TOOLS.items():
                if digest(Path("/mnt/c") / name[3:].replace("\\", "/")) != expected:
                    raise ValueError("Installed tool changed during execution")
            expected_exit = 2 if args.expect == "red" else 0
            if win["exitCode"] != expected_exit:
                raise ValueError("Unexpected child exit")
            if args.action == "bootstrap":
                write_new(action / "bootstrap.json", {"sha256": digest(action / "WindowsValidationJob.dll"),
                          "sourceSha256": digest(ROOT / "controller/WindowsValidationJob.cs")})
            elif args.action == "restore":
                write_new(action / "restore.json", {"inputs": graph_inputs(), "assets": generated("restore")})
            elif args.action == "build":
                write_new(action / "build.json", {"source": args.source, "artifacts": generated("build")})
            else:
                reports = list((action / "results").glob("*.trx"))
                if len(reports) != 1:
                    raise ValueError("Missing or ambiguous test evidence")
                counters = ET.parse(reports[0]).find(".//{*}Counters")
                if counters is None or int(counters.attrib["executed"]) != 10 or \
                        int(counters.attrib["failed"]) != (4 if args.expect == "red" else 0) or \
                        int(counters.attrib["passed"]) != (6 if args.expect == "red" else 10):
                    raise ValueError("Unexpected admitted case counts")
                result["tests"] = counters.attrib
            result["continuation_allowed"] = True
        except Exception as error:
            result["error_type"] = type(error).__name__
            if launched and not result["quiescent"]:
                windows_wait(powershell("-File", WINDOWS + "\\controller\\Stop-WindowsValidation.ps1",
                                        "-ActionName", action.name), 10)
                # Emergency controller absence is never accepted as Job quiescence.
        finally:
            result["utc"] = utc()
            if result["quiescent"]:
                result["evidence"] = {str(path.relative_to(action)): digest(path)
                                      for path in action.rglob("*") if path.is_file() and
                                      "home" not in path.relative_to(action).parts and
                                      "temp" not in path.relative_to(action).parts}
            write_new(local / "result.json", result)
        print(json.dumps({"action": local.name, "continuation_allowed": result["continuation_allowed"],
                          "quiescent": result["quiescent"], "tests": result.get("tests")}))
        return 0 if result["continuation_allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
