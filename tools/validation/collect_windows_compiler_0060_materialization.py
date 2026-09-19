"""Inactive, one-use passive Windows 0060 materialization observation.

The fixed selectors were derived from the accepted materialization DATA, not
from runtime receipts. Activate only an independently admitted captured inline
literal. This source must not be imported or executed for testing.
"""

ACTIVE = False
if not ACTIVE:
    raise RuntimeError('Inactive: independent exact observation admission is required')

import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
from contextlib import contextmanager

ROOT = Path('/var/tmp/azureauth-windows-slice-108')
OUTPUT = Path('/tmp/windows-compiler-0060-materialization-offline-root-v1')
ADMISSION = Path('/tmp/windows-compiler-0060-materialization-admission-root-v1.json')
MATERIALIZATION = {'bytes': 40097,
                   'sha256': '90d2dccdc19b8b328a7b1edbb0355bbf3f47718fa15276a7386fcc737dfcaabc'}
LIMITS = {'fileReads': 11, 'readCalls': 32, 'requestedBytes': 319499,
          'returnedBytes': 319488, 'outputBytes': 188416,
          'pathOperations': 8192, 'writeCalls': 12}
SMALL = 16384
INVENTORY_LIMIT = 131072

# Fixed role, kind, mapped Windows path, optional content ceiling.
# 21 directories + 101 metadata-only leaves + 3 opaque content leaves.
SELECTORS = (
    ('action-root', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060', 0),
    ('directory-01', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads', 0),
    ('directory-02', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/home', 0),
    ('directory-03', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/home/.dotnet', 0),
    ('directory-04', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/home/roaming', 0),
    ('directory-05', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/home/local', 0),
    ('directory-06', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/home/http', 0),
    ('directory-07', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/home/plugins', 0),
    ('directory-08', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/temp', 0),
    ('directory-09', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/empty-program-files', 0),
    ('directory-10', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/home/msbuild-user', 0),
    ('directory-11', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4', 0),
    ('directory-12', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/capture', 0),
    ('directory-13', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source', 0),
    ('directory-14', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src', 0),
    ('directory-15', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli', 0),
    ('directory-16', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core', 0),
    ('directory-17', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows', 0),
    ('directory-18', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli/obj', 0),
    ('directory-19', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/obj', 0),
    ('directory-20', 'directory', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/obj', 0),
    ('stage-source-01', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-01.bin', 0),
    ('stage-source-02', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-02.bin', 0),
    ('stage-source-03', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-03.bin', 0),
    ('stage-source-04', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-04.bin', 0),
    ('stage-source-05', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-05.bin', 0),
    ('stage-source-06', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-06.bin', 0),
    ('stage-source-07', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-07.bin', 0),
    ('stage-source-08', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-08.bin', 0),
    ('stage-source-09', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-09.bin', 0),
    ('stage-source-10', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-10.bin', 0),
    ('stage-source-11', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-11.bin', 0),
    ('stage-source-12', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-12.bin', 0),
    ('stage-source-13', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-13.bin', 0),
    ('stage-source-14', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-14.bin', 0),
    ('stage-source-15', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-15.bin', 0),
    ('stage-source-16', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-16.bin', 0),
    ('stage-source-17', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-17.bin', 0),
    ('stage-source-18', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-18.bin', 0),
    ('stage-source-19', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-19.bin', 0),
    ('stage-source-20', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-20.bin', 0),
    ('stage-source-21', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-21.bin', 0),
    ('stage-source-22', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-22.bin', 0),
    ('stage-source-23', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-23.bin', 0),
    ('stage-source-24', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-24.bin', 0),
    ('stage-source-25', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-25.bin', 0),
    ('stage-source-26', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-26.bin', 0),
    ('stage-source-27', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-27.bin', 0),
    ('stage-source-28', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-28.bin', 0),
    ('stage-source-29', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-29.bin', 0),
    ('stage-source-30', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-30.bin', 0),
    ('stage-source-31', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-31.bin', 0),
    ('stage-source-32', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-32.bin', 0),
    ('stage-source-33', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-33.bin', 0),
    ('stage-source-34', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/source-34.bin', 0),
    ('stage-restore-01', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-01.bin', 0),
    ('stage-restore-02', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-02.bin', 0),
    ('stage-restore-03', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-03.bin', 0),
    ('stage-restore-04', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-04.bin', 0),
    ('stage-restore-05', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-05.bin', 0),
    ('stage-restore-06', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-06.bin', 0),
    ('stage-restore-07', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-07.bin', 0),
    ('stage-restore-08', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-08.bin', 0),
    ('stage-restore-09', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-09.bin', 0),
    ('stage-restore-10', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-10.bin', 0),
    ('stage-restore-11', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-11.bin', 0),
    ('stage-restore-12', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/restore-12.bin', 0),
    ('stage-active-target', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/compiler-inputs-payloads/compiler-native-inputs.targets', 0),
    ('destination-source-01', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/global.json', 0),
    ('destination-source-02', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli/Authentication.Cli.csproj', 0),
    ('destination-source-03', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli/Program.cs', 0),
    ('destination-source-04', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli/packages.lock.json', 0),
    ('destination-source-05', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/Authentication.Core.csproj', 0),
    ('destination-source-06', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/AuthenticationRequest.cs', 0),
    ('destination-source-07', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/ProfileSyntax.cs', 0),
    ('destination-source-08', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/RequestCoordinator.cs', 0),
    ('destination-source-09', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/RequestInvocation.cs', 0),
    ('destination-source-10', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/RequestLifetime.cs', 0),
    ('destination-source-11', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/RequestSyntax.cs', 0),
    ('destination-source-12', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/ResultProjection.cs', 0),
    ('destination-source-13', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/packages.lock.json', 0),
    ('destination-source-14', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/Authentication.Windows.csproj', 0),
    ('destination-source-15', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/LocalWindowsProvider.cs', 0),
    ('destination-source-16', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/ManagedUserAgentHandler.cs', 0),
    ('destination-source-17', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/MsalAuthenticationProvider.cs', 0),
    ('destination-source-18', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/MsalBoundary.cs', 0),
    ('destination-source-19', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/MsalHttpClientFactory.cs', 0),
    ('destination-source-20', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/MsalSession.cs', 0),
    ('destination-source-21', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/MsalSessionFactory.cs', 0),
    ('destination-source-22', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/NativeWindowsHostObservations.cs', 0),
    ('destination-source-23', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/OwnedRequestHost.Native.cs', 0),
    ('destination-source-24', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/OwnedRequestHost.cs', 0),
    ('destination-source-25', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/RejectingWebUi.cs', 0),
    ('destination-source-26', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/WindowsDiagnostics.cs', 0),
    ('destination-source-27', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/WindowsHostAdmission.cs', 0),
    ('destination-source-28', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/WindowsLifetimePipe.cs', 0),
    ('destination-source-29', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/WindowsLoader.cs', 0),
    ('destination-source-30', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/WindowsProcess.cs', 0),
    ('destination-source-31', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/WindowsProfileSource.cs', 0),
    ('destination-source-32', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/WindowsStandardHandles.cs', 0),
    ('destination-source-33', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/packages.lock.json', 0),
    ('destination-source-34', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Directory.Build.props', 0),
    ('destination-restore-01', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli/obj/Authentication.Cli.csproj.nuget.dgspec.json', 0),
    ('destination-restore-02', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli/obj/Authentication.Cli.csproj.nuget.g.props', 0),
    ('destination-restore-03', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli/obj/Authentication.Cli.csproj.nuget.g.targets', 0),
    ('destination-restore-04', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Cli/obj/project.assets.json', 0),
    ('destination-restore-05', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/obj/Authentication.Core.csproj.nuget.dgspec.json', 0),
    ('destination-restore-06', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/obj/Authentication.Core.csproj.nuget.g.props', 0),
    ('destination-restore-07', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/obj/Authentication.Core.csproj.nuget.g.targets', 0),
    ('destination-restore-08', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Core/obj/project.assets.json', 0),
    ('destination-restore-09', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/obj/Authentication.Windows.csproj.nuget.dgspec.json', 0),
    ('destination-restore-10', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/obj/Authentication.Windows.csproj.nuget.g.props', 0),
    ('destination-restore-11', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/obj/Authentication.Windows.csproj.nuget.g.targets', 0),
    ('destination-restore-12', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/source/src/Authentication.Windows/obj/project.assets.json', 0),
    ('destination-active-target', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/compiler-native-inputs.targets', 0),
    ('marker-01', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/observers/compiler-native-inputs-5033607-v4/compiler-sequence.claim', 0),
    ('marker-02', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/home/.dotnet/10.0.401.dotnetFirstUseSentinel', 0),
    ('guard-load', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/guard-load.json', 0),
    ('subject-start-attempt', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/subject-start-attempt.json', 0),
    ('stdout', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/stdout.bin', 0),
    ('stderr', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/stderr.bin', 0),
    ('cancel', 'metadata', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/cancel', 0),
    ('started', 'content', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/started.json', 8192),
    ('invocation', 'content', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/invocation.json', 16384),
    ('windows-result', 'content', '/mnt/c/Temp/azureauth-windows-slice-108/actions/0060/windows-result.json', 32768),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def fail():
    raise ValueError('Fixed materialization observation rejected')


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail()
        result[key] = value
    return result


def check(state):
    if state['cancelled']:
        raise InterruptedError('Materialization observation cancelled')
    if time.monotonic_ns() >= state['deadline']:
        raise TimeoutError('Original observation deadline expired')


def charge(state, key, amount=1):
    check(state)
    state[key] += amount
    if state[key] > LIMITS[key]:
        fail()


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'bytes': info.st_size, 'mtimeNanoseconds': info.st_mtime_ns,
            'ctimeNanoseconds': info.st_ctime_ns}


def operation(state, function, *args, **kwargs):
    charge(state, 'pathOperations')
    value = function(*args, **kwargs)
    check(state)
    return value


@contextmanager
def directory(path, state):
    if not path.is_absolute() or '..' in path.parts or len(path.parts) - 1 > 16:
        fail()
    fd = operation(state, os.open, '/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = operation(state, os.open, name,
                              os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)
    check(state)


def snapshot(parent, name, state):
    try:
        return identity(operation(state, os.stat, name, dir_fd=parent, follow_symlinks=False))
    except FileNotFoundError:
        check(state)
        return None


def raw_read(parent, name, ceiling, state, expected=None):
    charge(state, 'fileReads')
    fd = operation(state, os.open, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                   dir_fd=parent)
    try:
        before = identity(operation(state, os.fstat, fd))
        if (not stat.S_ISREG(before['mode']) or not 0 <= before['bytes'] <= ceiling or
                (expected is not None and before != expected)):
            fail()
        chunks = []
        total = 0
        while True:
            requested = min(SMALL, before['bytes'] - total) if total < before['bytes'] else 1
            charge(state, 'readCalls')
            charge(state, 'requestedBytes', requested)
            chunk = os.read(fd, requested)
            charge(state, 'returnedBytes', len(chunk))
            if len(chunk) != requested and not (requested == 1 and total == before['bytes'] and not chunk):
                fail()
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > before['bytes']:
                fail()
        after = identity(operation(state, os.fstat, fd))
        leaf = snapshot(parent, name, state)
        if total != before['bytes'] or before != after or before != leaf:
            fail()
        return b''.join(chunks), before
    finally:
        os.close(fd)


def write_new(parent, name, raw, state):
    charge(state, 'outputBytes', len(raw))
    fd = operation(state, os.open, name,
                   os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        offset = 0
        while offset < len(raw):
            check(state)
            chunk = raw[offset:offset + SMALL]
            charge(state, 'writeCalls')
            count = os.write(fd, chunk)
            check(state)
            if count != len(chunk):
                fail()
            offset += count
        check(state)
        os.fsync(fd)
        check(state)
        os.fchmod(fd, 0o444)
        check(state)
        os.fsync(fd)
        check(state)
    finally:
        os.close(fd)
    check(state)
    os.fsync(parent)
    check(state)
    return {'bytes': len(raw), 'sha256': digest(raw)}


def hex_value(value, length=64):
    if (type(value) is not str or len(value) != length or
            any(c not in '0123456789abcdef' for c in value)):
        fail()


def pin_value(value):
    if (type(value) is not dict or set(value) != {'bytes', 'sha256'} or
            type(value['bytes']) is not int or not 1 <= value['bytes'] <= 16777216):
        fail()
    hex_value(value['sha256'])


def admission(state, admitted_sha):
    hex_value(admitted_sha)
    with directory(ADMISSION.parent, state) as parent:
        raw, _ = raw_read(parent, ADMISSION.name, SMALL, state)
    if digest(raw) != admitted_sha:
        fail()
    value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                       parse_constant=lambda _: fail())
    fields = {'schema', 'action', 'oneInvocation', 'acceptedTarget',
              'sourceSha256', 'runtimeReviewSha256', 'materializationData',
              'originalFailureAcceptance', 'originalCopyAcceptance',
              'originalInterpretationAcceptance', 'reservationSha256',
              'invocationSha256', 'capacity'}
    if (type(value) is not dict or set(value) != fields or encoded(value) != raw or
            value['schema'] != 'compiler-0060-materialization-admission-v1' or
            value['action'] != '0060' or value['oneInvocation'] is not True or
            value['materializationData'] != MATERIALIZATION or
            value['capacity'] != {'buildTest': 92, 'buildTestCeiling': 120,
                                  'synthetic': 52, 'syntheticCeiling': 80}):
        fail()
    target = value['acceptedTarget']
    if type(target) is not dict or set(target) != {'commit', 'tree', 'protocolSha256', 'waveSha256'}:
        fail()
    for key, length in (('commit', 40), ('tree', 40), ('protocolSha256', 64), ('waveSha256', 64)):
        hex_value(target[key], length)
    for key in ('sourceSha256', 'runtimeReviewSha256', 'reservationSha256', 'invocationSha256'):
        hex_value(value[key])
    for key in ('originalFailureAcceptance', 'originalCopyAcceptance',
                'originalInterpretationAcceptance'):
        pin_value(value[key])
    # Final independent literal review binds every DATA value to its accepted
    # original. No source, review, runtime, receipt or receipt-selected path is
    # opened here; only the exact externally admitted DATA hash grants entry.
    return value


def select_directory(path, state, nodes, held):
    if not path.is_absolute() or '..' in path.parts or len(path.parts) - 1 > 16:
        fail()
    if path in nodes:
        return nodes[path]
    parent = None if path == Path('/') else select_directory(path.parent, state, nodes, held)
    before = (identity(operation(state, os.stat, '/', follow_symlinks=False))
              if parent is None else
              snapshot(parent['fd'], path.name, state) if parent['fd'] is not None else None)
    fd = None
    missing = None
    if before is not None:
        if not stat.S_ISDIR(before['mode']):
            fail()
        if parent is None:
            fd = operation(state, os.open, '/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            fd = operation(state, os.open, path.name,
                           os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent['fd'])
        held.append(fd)
        if identity(operation(state, os.fstat, fd)) != before:
            fail()
    else:
        missing = str(path) if parent['fd'] is not None else parent['missingAncestor']
    node = {'path': path, 'parent': parent, 'fd': fd,
            'before': before, 'missingAncestor': missing}
    nodes[path] = node
    return node


def checkpoint_nodes(state, nodes):
    # All names are ancestors of the fixed selectors. Missing ancestors remain
    # bound to the same first missing component; no child discovery is attempted.
    for node in reversed(tuple(nodes.values())):
        parent = node['parent']
        after = (identity(operation(state, os.stat, '/', follow_symlinks=False))
                 if parent is None else
                 snapshot(parent['fd'], node['path'].name, state) if parent['fd'] is not None else None)
        if after != node['before']:
            fail()
        if node['fd'] is not None and identity(operation(state, os.fstat, node['fd'])) != after:
            fail()


def select_all(state, nodes, held):
    selected = []
    for role, kind, text, cap in SELECTORS:
        state.update(stage='metadata-before', role=role)
        path = Path(text)
        if kind == 'directory':
            node = select_directory(path, state, nodes, held)
            selected.append({'role': role, 'kind': kind, 'path': path, 'cap': cap,
                             'node': node, 'before': node['before'],
                             'missingAncestor': node['parent']['missingAncestor'], 'raw': None})
            continue
        parent = select_directory(path.parent, state, nodes, held)
        before = snapshot(parent['fd'], path.name, state) if parent['fd'] is not None else None
        if before is not None and not stat.S_ISREG(before['mode']):
            fail()
        selected.append({'role': role, 'kind': kind, 'path': path, 'cap': cap,
                         'node': parent, 'before': before,
                         'missingAncestor': parent['missingAncestor'], 'raw': None})
    if len(selected) != 125 or len({row['path'] for row in selected}) != 125:
        fail()
    return selected


def metadata_after(state, selected):
    for row in selected:
        state.update(stage='metadata-after', role=row['role'])
        node = row['node']
        if row['kind'] == 'directory':
            parent = node['parent']
            after = snapshot(parent['fd'], row['path'].name, state) if parent['fd'] is not None else None
        else:
            after = snapshot(node['fd'], row['path'].name, state) if node['fd'] is not None else None
        if after != row['before']:
            fail()
        row['after'] = after


def collect(state):
    state.update(stage='admission', role=None)
    admitted = admission(state, sys.argv[1])
    state.update(stage='lock', role=None)
    with directory(ROOT, state) as root:
        root_identity = identity(operation(state, os.fstat, root))
        lock = operation(state, os.open, 'action.lock',
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        try:
            lock_identity = identity(operation(state, os.fstat, lock))
            if not stat.S_ISREG(lock_identity['mode']) or snapshot(root, 'action.lock', state) != lock_identity:
                fail()
            check(state)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            check(state)
            held = []
            try:
                nodes = {}
                selected = select_all(state, nodes, held)
                checkpoint_nodes(state, nodes)
                for row in selected:
                    if row['kind'] == 'content' and row['before'] is not None:
                        state.update(stage='initial-read', role=row['role'])
                        raw, _ = raw_read(row['node']['fd'], row['path'].name,
                                          row['cap'], state, row['before'])
                        if (row['role'] in ('started', 'invocation') and
                                digest(raw) != admitted['reservationSha256' if row['role'] == 'started'
                                                       else 'invocationSha256']):
                            fail()
                        row['raw'] = raw
                state.update(stage='output-create', role=None)
                with directory(OUTPUT.parent, state) as destination:
                    destination_identity = identity(operation(state, os.fstat, destination))
                    operation(state, os.mkdir, OUTPUT.name, mode=0o700, dir_fd=destination)
                    output = operation(state, os.open, OUTPUT.name,
                                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination)
                    try:
                        output_id = identity(operation(state, os.fstat, output))
                        if output_id != snapshot(destination, OUTPUT.name, state):
                            fail()
                        for row in selected:
                            if row['raw'] is not None:
                                state.update(stage='copy-write', role=row['role'])
                                copy_name = row['role'] + '.bin'
                                copied = write_new(output, copy_name, row['raw'], state)
                                state.update(stage='copy-readback', role=row['role'])
                                reread, copy_identity = raw_read(output, copy_name, row['cap'], state)
                                if reread != row['raw'] or stat.S_IMODE(copy_identity['mode']) != 0o444:
                                    fail()
                                row['copy'] = dict(copied, file=copy_name, identity=copy_identity)
                        for row in selected:
                            if row['raw'] is not None:
                                state.update(stage='original-continuity', role=row['role'])
                                reread, _ = raw_read(row['node']['fd'], row['path'].name,
                                                    row['cap'], state, row['before'])
                                if reread != row['raw']:
                                    fail()
                        metadata_after(state, selected)
                        state.update(stage='directory-continuity', role=None)
                        checkpoint_nodes(state, nodes)
                        rows = []
                        for row in selected:
                            status = ('ancestor-absent' if row['missingAncestor'] is not None else
                                      'absent' if row['before'] is None else 'present')
                            item = {'role': row['role'], 'kind': row['kind'], 'path': str(row['path']),
                                    'maximumContentBytes': row['cap'], 'status': status,
                                    'missingAncestor': row['missingAncestor'],
                                    'before': row['before'], 'after': row['after']}
                            if 'copy' in row:
                                item['copy'] = row['copy']
                            rows.append(item)
                        report = {'schema': 'compiler-0060-materialization-inventory-v1',
                                  'action': '0060', 'admission': admitted, 'selectors': rows,
                                  'originalOutcome': 'failed', 'originalLifetime': 'unresolved',
                                  'metadataMeaning': 'Two finite checkpoints; no atomic or continuing guarantee.',
                                  'graphAccepted': False, 'artifactAccepted': False,
                                  'continuation_allowed': False, 'independentObservationAccepted': False,
                                  'sourceLimits': LIMITS, 'normalCompletion': False,
                                  'finalOriginalToolExitRequired': True}
                        raw_report = encoded(report)
                        if len(raw_report) > INVENTORY_LIMIT:
                            fail()
                        state.update(stage='inventory-write', role=None)
                        pin = write_new(output, 'inventory.json', raw_report, state)
                        state.update(stage='inventory-readback', role=None)
                        reread, inventory_identity = raw_read(output, 'inventory.json', INVENTORY_LIMIT, state)
                        if reread != raw_report or stat.S_IMODE(inventory_identity['mode']) != 0o444:
                            fail()
                        state.update(stage='output-finalization', role=None)
                        check(state)
                        os.fsync(output)
                        check(state)
                        for row in selected:
                            if 'copy' in row and snapshot(output, row['copy']['file'], state) != row['copy']['identity']:
                                fail()
                        if snapshot(output, 'inventory.json', state) != inventory_identity:
                            fail()
                        final_output = identity(operation(state, os.fstat, output))
                        if (snapshot(destination, OUTPUT.name, state) != final_output or
                                any(final_output[k] != output_id[k] for k in ('device', 'inode', 'mode'))):
                            fail()
                        with directory(OUTPUT.parent, state) as current_destination:
                            now = identity(operation(state, os.fstat, current_destination))
                            if (any(now[k] != destination_identity[k] for k in ('device', 'inode', 'mode')) or
                                    snapshot(current_destination, OUTPUT.name, state) != final_output):
                                fail()
                    finally:
                        os.close(output)
                    check(state)
                    os.fsync(destination)
                    check(state)
            finally:
                for fd in reversed(held):
                    os.close(fd)
            state.update(stage='lock-finalization', role=None)
            if (identity(operation(state, os.fstat, lock)) != lock_identity or
                    snapshot(root, 'action.lock', state) != lock_identity):
                fail()
            with directory(ROOT, state) as current_root:
                if (identity(operation(state, os.fstat, current_root)) != root_identity or
                        snapshot(current_root, 'action.lock', state) != lock_identity):
                    fail()
        finally:
            os.close(lock)
    check(state)
    return pin


def main():
    began = time.monotonic_ns()
    state = dict.fromkeys(LIMITS, 0)
    state.update(deadline=began + 90_000_000_000, cancelled=False, stage='admission', role=None)
    handlers = {}
    def cancel(_number, _frame):
        state['cancelled'] = True
    pin = None
    error_type = None
    try:
        if len(sys.argv) != 2:
            fail()
        for number in (signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.signal(number, cancel)
        pin = collect(state)
        state.update(stage='finalization', role=None)
    except BaseException as error:
        error_type = type(error).__name__
    finally:
        for number, handler in handlers.items():
            try:
                signal.signal(number, handler)
            except BaseException:
                error_type = 'HandlerRestoreFailure'
                state.update(stage='finalization', role=None)
    if state['cancelled'] or time.monotonic_ns() >= state['deadline']:
        error_type = 'CancelledOrLate'
    allowed = {'ValueError', 'OSError', 'FileNotFoundError', 'PermissionError',
               'BlockingIOError', 'FileExistsError', 'InterruptedError', 'TimeoutError',
               'HandlerRestoreFailure', 'CancelledOrLate'}
    frame = {'schema': 'compiler-0060-materialization-transport-v1',
             'normalCompletion': error_type is None,
             'stage': state['stage'], 'role': state['role'],
             'exceptionType': error_type if error_type in allowed or error_type is None else 'OtherException',
             'inventory': pin, 'counters': {key: state[key] for key in LIMITS}}
    try:
        sys.stdout.buffer.write(encoded(frame))
        sys.stdout.buffer.flush()
        check(state)
    except BaseException:
        return 1
    return 0 if error_type is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
