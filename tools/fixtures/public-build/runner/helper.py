#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


SOURCE_COMMIT = "de20930c34b3b86c8a0ed7bbdeeca3f662dae918"
PROJECTS = (
    "src/AdoPat/AdoPat.csproj",
    "src/AdoPat.Test/AdoPat.Test.csproj",
    "src/AzureAuth/AzureAuth.csproj",
    "src/AzureAuth.Test/AzureAuth.Test.csproj",
    "src/MSALWrapper.Benchmark/MSALWrapper.Benchmark.csproj",
    "src/MSALWrapper/MSALWrapper.csproj",
    "src/MSALWrapper.Test/MSALWrapper.Test.csproj",
    "src/TestHelper/TestHelper.csproj",
)


def normalized_arguments(role: str) -> list[str]:
    arguments = sys.argv[1:]
    if role not in {"git", "dotnet"}:
        return arguments
    checkout = Path(os.environ["HOME"]).parent / "checkout"
    retained = re.compile(r"/proc/self/fd/[0-9]+")
    normalized: list[str] = []
    for index, argument in enumerate(arguments):
        value = retained.sub(str(checkout), argument)
        if (
            role == "dotnet"
            and index > 0
            and arguments[index - 1] == "--configfile"
            and not os.path.isabs(value)
        ):
            value = os.path.abspath(value)
        normalized.append(value)
    return normalized


def write_log(role: str) -> None:
    if role == "mise":
        root = Path(os.environ["MISE_DATA_DIR"])
    else:
        root = Path(os.environ["HOME"])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (root / f"fake-{role}.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "role": role,
                    "argv": normalized_arguments(role),
                    "runtime_argv": sys.argv[1:],
                    "cwd": str(Path.cwd()),
                    "env_keys": sorted(os.environ),
                    "path": os.environ.get("PATH"),
                    "time_ns": time.time_ns(),
                },
                sort_keys=True,
            )
            + "\n"
        )


def fake_mise() -> int:
    write_log("mise")
    toolchain = Path(os.environ["MISE_DATA_DIR"])
    selection = toolchain.parents[1] / "selections" / toolchain.name
    control_path = selection.parent / f"{selection.name}.fake-control.json"
    control = json.loads(control_path.read_text()) if control_path.exists() else {}
    if sys.argv[1:] == ["--version"]:
        print(
            "0.0.0 synthetic mismatch"
            if control.get("mismatch_mise_version")
            else "2026.8.10 linux-x64 (synthetic)"
        )
        return 0
    install_root = (
        Path(os.environ["MISE_DATA_DIR"])
        / "installs/http-dotnet-sdk/8.0.424"
    )
    install_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    dotnet = install_root / "dotnet"
    shutil.copyfile(Path(__file__), dotnet)
    dotnet.chmod(0o700)
    deps = (
        install_root
        / "sdk/8.0.424/NuGet.CommandLine.XPlat.deps.json"
    )
    deps.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    deps.write_text(
        json.dumps(
            {
                "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0"},
                "libraries": {
                    "NuGet.CommandLine.XPlat/6.11.1": {"type": "project"}
                },
            }
        ),
        encoding="utf-8",
    )
    return 0


def fake_git() -> int:
    write_log("git")
    arguments = sys.argv[1:]
    if arguments[0] == "init":
        checkout = Path(arguments[1])
        (checkout / ".git").mkdir(mode=0o700, parents=True)
        (checkout / ".git/index").write_bytes(b"synthetic-index")
        (checkout / ".git/HEAD").write_text(f"{SOURCE_COMMIT}\n", encoding="ascii")
        tracked = ["AzureAuth.sln", "nuget.config", *PROJECTS]
        for relative in tracked:
            path = checkout / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text(f"synthetic {relative}\n", encoding="utf-8")
        return 0
    checkout = Path(arguments[1])
    command = arguments[2]
    mode_root = Path(os.environ["HOME"]).parent
    selection = mode_root.parent
    control_path = selection.parent / f"{selection.name}.fake-control.json"
    control = json.loads(control_path.read_text()) if control_path.exists() else {}
    fail_mode = control.get("fail_git_fetch_mode")
    mode_id = mode_root.name
    if command == "fetch" and isinstance(fail_mode, str) and fail_mode == mode_id:
        return 11
    fail_checkout_mode = control.get("fail_git_checkout_mode")
    if (
        command == "checkout"
        and isinstance(fail_checkout_mode, str)
        and fail_checkout_mode == mode_id
    ):
        return 12
    if command == "checkout" and control.get("occupy_public_config"):
        generated = mode_root / "generated/only-nuget.org.config"
        generated.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        generated.write_text("preexisting\n", encoding="utf-8")
    if command in {"fetch", "checkout"}:
        return 0
    if command == "rev-parse":
        mismatch_mode = control.get("mismatch_git_head_mode")
        print(
            "0" * 40
            if isinstance(mismatch_mode, str)
            and mismatch_mode == mode_id
            else SOURCE_COMMIT
        )
        return 0
    if command == "ls-files":
        tracked = ["AzureAuth.sln", "nuget.config", *PROJECTS]
        sys.stdout.buffer.write(b"\0".join(item.encode() for item in tracked) + b"\0")
        return 0
    return 2


def fake_dotnet() -> int:
    write_log("dotnet")
    runtime_arguments = sys.argv[1:]
    arguments = normalized_arguments("dotnet")
    mode_id = Path(os.environ["HOME"]).parent.name
    selection = Path(os.environ["HOME"]).parent.parent
    control_path = selection / ".fake-control.json"
    if not control_path.exists():
        control_path = selection.parent / f"{selection.name}.fake-control.json"
    control = json.loads(control_path.read_text()) if control_path.exists() else {}
    if arguments == ["--info"]:
        fail_info_mode = control.get("fail_dotnet_info_mode")
        if isinstance(fail_info_mode, str) and fail_info_mode == mode_id:
            return 13
        mismatch_info_mode = control.get("mismatch_dotnet_info_mode")
        print(
            ".NET SDK synthetic 0.0.0"
            if isinstance(mismatch_info_mode, str)
            and mismatch_info_mode == mode_id
            else ".NET SDK synthetic 8.0.424"
        )
        return 0
    if arguments == ["nuget", "locals", "all", "--list"]:
        invalid_mode = control.get("invalid_cache_locations_mode")
        if isinstance(invalid_mode, str) and invalid_mode == mode_id:
            print("http-cache: duplicate")
            print("http-cache: duplicate")
            return 0
        print(f"info : http-cache: {os.environ['NUGET_HTTP_CACHE_PATH']}/")
        print(f"info : global-packages: {os.environ['NUGET_PACKAGES']}//")
        print(f"info : temp: {os.environ['NUGET_SCRATCH']}/")
        print(f"info : plugins-cache: {os.environ['NUGET_PLUGINS_CACHE_PATH']}/")
        return 0
    command_id = control.get("command_ids", {}).get(json.dumps(arguments))
    if command_id == control.get("sensitive_command"):
        print("client_secret=synthetic-secret")
        return 0
    if command_id == control.get("overflow_command"):
        block = b"x" * 65536
        for _ in range(32):
            sys.stdout.buffer.write(block)
            sys.stderr.buffer.write(block)
        return 0
    if command_id == control.get("overflow_sensitive_command"):
        block = b"x" * 65536
        for _ in range(17):
            sys.stdout.buffer.write(block)
        os.write(sys.stdout.fileno(), b"\nclient_secret=synthetic-secret\n")
        return 0
    if command_id == control.get("mutate_command"):
        checkout = Path.cwd()
        (checkout / "AzureAuth.sln").write_text("mutated\n", encoding="utf-8")
    if command_id == control.get("chmod_command"):
        checkout = Path.cwd()
        (checkout / "AzureAuth.sln").chmod(0o700)
    if command_id == control.get("untracked_command"):
        checkout = Path.cwd()
        (checkout / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    if command_id == control.get("source_type_command"):
        checkout = Path.cwd()
        source = checkout / "AzureAuth.sln"
        source.unlink()
        source.mkdir()
    if command_id == control.get("replace_checkout_during_command"):
        Path(control["checkout_entered_marker"]).write_text(
            command_id,
            encoding="ascii",
        )
        release = Path(control["checkout_release_marker"])
        deadline = time.monotonic() + 10
        while not release.exists():
            if time.monotonic() > deadline:
                return 98
            time.sleep(0.01)
        (Path.cwd() / "AzureAuth.sln").write_text(
            "mutated retained checkout\n",
            encoding="utf-8",
        )
    if command_id == control.get("sleep_command"):
        time.sleep(5)
    asset_modes = control.get("asset_modes", [])
    if arguments and arguments[0] == "restore" and any(
        mode == mode_id for mode in asset_modes
    ):
        fixture = Path(control["asset_fixture"])
        assets = json.loads(fixture.read_text(encoding="utf-8"))
        checkout = Path.cwd()
        if any(
            mode == mode_id
            for mode in control.get("sensitive_asset_modes", [])
        ):
            assets["token"] = "do-not-publish"
        packages = os.environ["NUGET_PACKAGES"]
        source = (
            "https://api.nuget.org/v3/index.json"
            if mode_id == "public-only"
            else "https://pkgs.dev.azure.com/office/_packaging/Office/nuget/v3/index.json"
        )
        restore = assets["project"]["restore"]
        config_file = next(
            runtime_arguments[index + 1]
            for index, argument in enumerate(runtime_arguments[:-1])
            if argument == "--configfile"
        )
        restore["configFilePaths"] = [
            os.path.abspath(config_file)
        ]
        restore["packagesPath"] = packages
        restore["projectPath"] = str(checkout / "src/TestHelper/TestHelper.csproj")
        restore["sources"] = {source: {}}
        assets["packageFolders"] = {f"{packages.rstrip('/')}/": {}}
        artifacts = next(
            value.split("=", 1)[1]
            for value in arguments
            if value.startswith("-p:ArtifactsPath=")
        )
        destination = Path(artifacts) / "obj/TestHelper/project.assets.json"
        if any(
            mode == mode_id
            for mode in control.get("symlink_asset_modes", [])
        ):
            outside = selection.parent / f"{selection.name}-outside-assets"
            outside.mkdir(mode=0o700, parents=True, exist_ok=True)
            component = destination.parent
            component.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            component.symlink_to(outside, target_is_directory=True)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_text(json.dumps(assets), encoding="utf-8")
    if command_id == control.get("fail_command"):
        return 9
    fail_restore_mode = control.get("fail_restore_mode")
    if (
        arguments
        and arguments[0] == "restore"
        and isinstance(fail_restore_mode, str)
        and fail_restore_mode == mode_id
    ):
        return 8
    return 0


def main() -> int:
    executable = Path(sys.argv[0]).name
    descriptor_launch = (
        executable.isdigit()
        and len(sys.argv) > 1
        and sys.argv[1] in {"--version", "--no-env"}
    )
    if executable == "mise" or descriptor_launch:
        return fake_mise()
    if executable == "git":
        return fake_git()
    if executable == "dotnet":
        return fake_dotnet()
    mode = sys.argv[1]
    if mode == "argv":
        print(json.dumps(sys.argv[2:]))
        return 0
    if mode == "env":
        names = sys.argv[2:]
        print(json.dumps({name: os.environ.get(name) for name in names}, sort_keys=True))
        return 0
    if mode == "count":
        path = Path(sys.argv[2])
        count = int(path.read_text(encoding="ascii")) + 1 if path.exists() else 1
        path.write_text(str(count), encoding="ascii")
        return int(sys.argv[3])
    if mode == "sleep":
        time.sleep(float(sys.argv[2]))
        return 0
    if mode == "output":
        remaining = int(sys.argv[2])
        block = b"x" * 65536
        while remaining:
            chunk = block[:remaining]
            sys.stdout.buffer.write(chunk)
            sys.stderr.buffer.write(chunk)
            remaining -= len(chunk)
        return 0
    if mode == "sensitive":
        sys.stdout.write("token=do-not-persist\n")
        sys.stderr.write("Authorization: Bearer do-not-persist\n")
        return 0
    if mode == "grandchild":
        subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "sleep", sys.argv[2]],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=dict(os.environ),
        )
        time.sleep(0.15)
        return 0
    if mode == "instant-grandchild":
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "sleep", "30"],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=dict(os.environ),
        )
        Path(sys.argv[2]).write_text(str(child.pid), encoding="ascii")
        time.sleep(30)
        return 0
    if mode == "pipe-grandchild":
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__)), "sleep", "30"],
            shell=False,
            stdin=subprocess.DEVNULL,
            env=dict(os.environ),
        )
        Path(sys.argv[2]).write_text(str(child.pid), encoding="ascii")
        return 0
    if mode == "fork-churn":
        deadline = time.monotonic() + float(sys.argv[2])
        while time.monotonic() < deadline:
            subprocess.Popen(
                [sys.executable, str(Path(__file__)), "sleep", "0.05"],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=dict(os.environ),
            )
            time.sleep(0.002)
        return 0
    if mode == "exit":
        return int(sys.argv[2])
    raise ValueError(f"unknown helper mode: {mode}")


if __name__ == "__main__":
    raise SystemExit(main())
