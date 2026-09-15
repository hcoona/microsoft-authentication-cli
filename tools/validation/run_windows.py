"""Run one admitted Windows managed-file/process action under the accepted Slice protocol.

The WSL history survives failed Windows starts. No authentication, publishing,
package download, arbitrary command, or automatic retry is exposed here.
"""

import argparse
import base64
from contextlib import contextmanager
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
WAVE = "956aebe0e19cce7dbd08dcaa7fe83a9ef9e01f7c"
GRANT = "a0f741b59e09f1eb95594dbfde7a6e634d962210"
CONTROLLERS = ("run_windows.py", "Invoke-WindowsValidation.ps1",
               "Stop-WindowsValidation.ps1", "WindowsValidationJob.cs")
PROJECT = "Windows.slnx"
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
# Exact stopped-result disposition; the original failed receipts remain unchanged.
DISPOSED_OWNED_PROCESS_RED = {
    "started.json": "9ad80c13d63adec92abc0557b01ff9006e860d714f36455917b17a904f06d416",
    "windows-input.json": "a926fad126c073e6a0fe3127dfccc34fa3e7f846f6d920778001a66272a17bc5",
    "result.json": "70a2f2e0d177ce230ac7765e95f8682200878a466b40b698fb9af034e0615572",
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
DISPOSED_WINDOWS_TEST = {
    "started.json": "4fb0599b8aaacbcbb2099a2254426b3ac8a2ff16cfd5cacb90222c08b648a8c9",
    "windows-input.json": "3064a64bf43690bc5efc0c9022c6fe52da8d3a36880ec76efe5d691b1fdc1989",
    "result.json": "4ef1514ecd4e19cf02657a38ed73e5e920cb30cf38df9d54472ca89b3784f6ff",
}

# Exact accepted pre-subject attendance expiry; never a general failed-action bypass.
DISPOSED_WINDOWS_ATTENDANCE = {
    "result.json": "c15dd433a4d9a104d27e529909f7a8ec28e5b38d2bfa2dcad450e469a6b94338",
    "started.json": "f4d69974990731e5a32f35df7c71935982c7fc8f480ef58d90395567cfc75e29",
    "windows-input.json": "5b47542488f8d4ec2db81cecb3b0d8fa39e349d0c9e4cb9c71a69795b61547d1",
}

# Exact accepted UI-admission attendance expiry; the failed charge remains retained.
DISPOSED_UI_ATTENDANCE = {
    "result.json": "6c4596568982d0e44924d58d8386dee0b58f6d7f73a809047bd34860a46b1766",
    "started.json": "4785c692765970cd909c341470e3d8e750f448e45bc53ad3165a70e0cdaf46a7",
    "windows-input.json": "e07476d8b99467266698e3f212c2b687c3538b57eb8484d9812456713e1f618c",
}

# Exact second UI-admission expiry, including its completed wrapper migration.
DISPOSED_UI_ATTENDANCE_0034 = {
    "result.json": "2ba6cd4445dba723dcfd30dca57772c751ccf9d3fb775e5e0bfb688da2c21d83",
    "started.json": "74efac252f02bd01ca8ab75d4d6cc179d5f1fdfcfa4bcd7132f52712d03ec940",
    "windows-input.json": "e937ebb25470f0ec025af48a4e87d5683777423e9e283d5cc328880f9f98b46f",
}
ATTENDANCE_SECONDS = 14400

EXTENDED_ATTENDANCE_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "5e03199cf13fa0215d159c5c57699c352b737ed2e3f3a810026d623cc30471c2",
    "Invoke-WindowsValidation.ps1": "c91e044adaa941bb999cfe0c579c6cea0e97808331b7cde8e823a7de41b79c1b",
}
TEST_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "bec5e035be9d54afd871bee648f2018f4ead6fec747c871f8c1c98f9a31db105",
    "Invoke-WindowsValidation.ps1": "131a4834275afe9e7041eb8d5cc106f9220127a68a75fd2383d021309a99ae9d",
}


# Exact cache additions and one-time transition after the accepted file loop.
PROCESS_PREVIOUS_CONTROLLERS = {'run_windows.py': 'f0259f9d8b48cae8f4bb00bcc0c905cf2edf99dd3e131483920048d089e0b990',
 'Invoke-WindowsValidation.ps1': '2255721d7774bb0cca0cf5819cb673f7c2b3cde7afd3ef0d00749df9a97f7223'}
PROCESS_ARCHIVES = {'microsoft.identity.client.4.83.1.nupkg': (4391519,
                                            '692ae5e6b961a2ef71b747a9877f7a7f0460a03f9fb2edc0fa7e4d457a5419a0f564afae53c6296b7e75e0ab2b1c61b3f621a9d56e99945bb047b02dcfe9a2bd',
                                            'jOLIrZ3cynoqHLLO1cXplFFabrhrMEYs/EuKHvmCyrOm1axqiVFT6nCSnHxk7w5+d2BeQfCdM12Yf/0X7OeS1g=='),
 'microsoft.identity.client.broker.4.83.1.nupkg': (90323,
                                                   '9923928bde2049ed3ec125f871eb37f125a2bb28d20e0d5ebdf59d1a7cb1f37858f4c7d818dd25fd72f1fa7ae96a01a1320d1a21bb3ba3a1379d3fe37463f2ec',
                                                   'r5F/Iwm/DeRA8JP2yxpW31gDxXfehvDilI4U6t80bAhnass0Czjwkdyx8LbZYbeeTB5J8jUp90qSxIf/tBeJ0A=='),
 'microsoft.identity.client.nativeinterop.0.20.3.nupkg': (20066978,
                                                          'e8d30c22acc6c14d91f09c9e8204278357f2500a11e1e7befb1443f0e806a9dd5522938d37733bfe3de11a1c4e30ccea4755f80fcd1f9de6d8c87a88910ae5cd',
                                                          'k8f/a/IdBYU905Js0QUd0nuoN680adS393QhrcOyAvCbnteKCNUdzuMIi9pROlJrbjxPqQXRNcf3a9cjE65UfA=='),
 'microsoft.identitymodel.abstractions.8.14.0.nupkg': (115275,
                                                       '175ef8bf78b63f3c327e680d5cf7721d74f29e96460e686b22b4e67c264fb036a7a9bea1473f4a5b487337ab7a560c861b51ed1aa744777f303362262b01a8b4',
                                                       'iwbCpSjD3ehfTwBhtSNEtKPK0ICun6ov7Ibx6ISNA9bfwIyzI2Siwyi9eJFCJBwxowK9xcA1mj+jBWiigeqgcQ=='),
 'microsoft.dotnet.ilcompiler.10.0.12.nupkg': (94736,
                                               'a9e3932bd0d16d6c78fde79b5c6d6fe74ca4104983f54be9f09d62085aa7cf7d1683cb3cbdf3dddad3e9a9a7b4c0c9d262676f28299308483afd96b34acba562',
                                               'AawF393Q+VkdrnrnI1gu612zh5iqpa1AGSvnKCQ3IkMgSKJXIQbO1sXYRgEzOU4f0cPZ6MaCCF29xZSGWlmbuQ=='),
 'runtime.win-x64.microsoft.dotnet.ilcompiler.10.0.12.nupkg': (11908112,
                                                               '3875d56e9404026f57c1b1a0673c722b5485340b693422c7c9ea118f40301b51ed173871ee525818080de8230ee0ac6147c56e352d4da8929532b3b3959d684d',
                                                               'clsgU9GnioCJ+PBzQTCoJHxLXRU+7O/BzYrwRT8CUP7jgyYjNgJmNsQ/kbzAA7MG5kDvFoFvIBGHGzYdINh/EQ=='),
 'microsoft.netcore.app.runtime.nativeaot.win-x64.10.0.12.nupkg': (29492822,
                                                                   'bc56dd1d11b4a49874cc12cfa66f0163fa1a353fb84d8158e336e2eb779ebd7ae0aa487d660bc85043c833589a33f348ea6674cf1bf61744fe1ae9d38168e9c8',
                                                                   'MPm78CKSJf8Sb0nbXgvzedp2uwFQX4JONl618NhEeAEznK9JLzQ6ETfJZ+UcoW5ScTqa27a+JGQDXD3bUAMTrA=='),
 'microsoft.netcore.app.runtime.win-x64.10.0.12.nupkg': (39968868,
                                                         '39afcb222032eabebe2c7fa51a37c491c6b0f456796ad7888431971b8eef4f689caee5454260398ce0ffafe491c565891b35e73afc67585a3e4c4bde995710ee',
                                                         'H3eh1w8Yevp6yO2+R3zbOPfwJ1vs2c/5PKa1ez7igGCF8EIycnzZr8gTjeVBAKjCPbyGuOdMSazLUnNqMsfTkw==')}
INSTALLED_PACKS = {'Microsoft.NETCore.App.Ref': ('10.0.12',
                               7188850,
                               'b8df7c98c76bba344b41d20151dc79e5a4dc764b5fdb893844fdfdb895be05247d31cb4e93452ba668beb2f3f62a3f30ed8b1242e06b7a0c53b11125fc69ba28',
                               ['analyzers/', 'data/', 'ref/']),
 'Microsoft.NETCore.App.Host.win-x64': ('10.0.12',
                                        5790931,
                                        '33c2760f5936e1eb30609fc368974761bc331eb720fa0593bf92f9f050c6d91d67f673a22783160ab84c16d6736e8c02c10066ced6c06cceed378f5cbaa78588',
                                        ['runtimes/'])}
FILE_CASES = ['ExplicitFilePreservesSelectedProfileAndRequest ("personal@example.test")',
 'ExplicitFilePreservesSelectedProfileAndRequest ("work@example.test")',
 'FileSizeLimitAppliesBeforeAuthentication (65536)',
 'FileSizeLimitAppliesBeforeAuthentication (65537)',
 'ReplacingFileAfterAdmissionCannotChangeTheInFlightProfile',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("missing")',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("directory")',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("malformed-json")',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("invalid-utf8")',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("sharing-denied")']
PROCESS_CASES = {'RootHelpCompletesWithoutAuthentication': 'help',
 'MalformedAuthenticationReturnsTheBootstrapFailure': 'malformed',
 'SelectedRequestReturnsOneSuccessDespiteBrokenDiagnostics': 'success',
 'FlaggedRegularFileStopsBeforeProfileAndProvider': 'file-stdin',
 'AlreadyClosedLifetimePipeCancelsBeforeAuthentication': 'closed-stdin',
 'WriterClosureRejectsLateSuccessAndEndsTheProcess': 'close-pending',
 'ClosedStdinWithoutTheFlagDoesNotCancel': 'unused-stdin',
 'LifetimePipePayloadIsIgnoredAndClosureStillCancels': 'data-close',
 'DeadlineEndsUncooperativeWorkWithinTheProcessBound': 'deadline',
 'BrokenResultReaderEndsWithTransportFailure': 'broken-output',
 'UndrainedResultPipeCannotKeepTheProcessAlive': 'blocked-output',
 'BlockedDiagnosticsDoNotChangeTheAuthenticationResultOrKeepTheProcessAlive': 'blocked-diagnostics'}
ARCHIVES.update({name: values[:2] for name, values in PROCESS_ARCHIVES.items()})
SUPERSEDED_LOCKS = (
    "src/Authentication.Core/packages.lock.json",
    "src/Authentication.Windows/packages.lock.json",
    "tests/Authentication.Windows.Scenarios/packages.lock.json",
)

OWNED_HOST_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "1b1c9aa5bd563b8c0c9aba61dc57774cc1f2f30296eb836b8bb4536acd23ecf6",
    "Invoke-WindowsValidation.ps1": "a42e9dc7b85972ba980ac3405e6ebd74892c21e1f59be59f0f49143dac17b100",
}
OWNED_HOST_PRIOR_FINAL = "919c9e080c088138976029b4b426cc7973e8ed94384eac465ff43bc29a50abcd"
OWNED_HOST_PRIOR_START = "00c13bdb95279b555ec1f3b11a2092d2ce7db33e38dc1622de613a0ce20dac29"

WAVE_REFRESH_PREVIOUS_CONTROLLERS = {
    "Invoke-WindowsValidation.ps1": "af0b1c461171179637f12efe02d8a8151d77f258352524a5ffdacd99e30af445",
    "run_windows.py": "0b3997c5ce411f2da45eb1c4cb20030f543e2c5754e1fc32f111699a64ab330e",
}
WAVE_REFRESH_PRIOR_START = "7ae88b209f6a36ba4851508376d7d92811fe6262218f12e5a95fb055cc5de857"
WAVE_REFRESH_PRIOR_FINAL = "58ce379fe433a11573b31163b27bfe98321d9544768cf8109d9f6d819b3a427b"

ATTENDANCE_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "0e5a2a3360e19200a0e81b84f87b42d94a96e12ca56524c85800c55378574b30",
}

UI_ATTENDANCE_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "0046cb65cba438fc2650b4d8178197e18a70694177ababa9c7186f87ae6cc5ef",
}

ADAPTER_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "93486d23aff1ade31b314c0d0c588af250ca200068297539507517a5946d2bb6",
    "Invoke-WindowsValidation.ps1": "bf90ffed77171eb553eed0350dabddbfc14966e1e3584fea3e77e867b6ec559f",
}
ADAPTER_PRIOR_FINAL = "d71e129cfdeb8d47fc83146319242c2948d4948240fd15cee39914b45ba4653d"
ADAPTER_PRIOR_START = "527ed232989800a81fa9eaced39cd66c24c7eb01c309ca5f24ea83746f257f1a"
ADAPTER_RED = {'Authentication.Windows.Scenarios.MsalAdapterScenarios.ConsentRequirementHonorsInteractionPermission': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.SilentClaimsReachOneContinuationAndSecondChallengeStops': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.AccessDeniedWinsOverUiRequiredAndRetryHint': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.Structured65004WinsOverRetryHint': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.DenialTextAndNativeCodeDoNotImplyEntraDenial': 'Passed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.DuplicateErrorCodesDoNotCreateDenial': 'Passed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.NonNumericErrorCodesDoNotCreateDenial': 'Passed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.MalformedOrOverBudgetBodiesDoNotCreateDenial': 'Passed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.ProviderUserCancellationRemainsCancelled': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalCancellationWinsOverDenial': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalDeadlineWinsLateProviderCancellation': 'Passed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.HttpTimeoutDoesNotConsumeRequestDeadline': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.RetryableProviderStopsWithoutApplicationRetry': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.RecognizedNetworkErrorStopsWithoutRetry': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.UnknownProviderConfigurationStaysInternal': 'Passed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.UnexplainedCancellationStaysInternal': 'Passed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.UserMismatchWinsOverRetryHint': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.ResultProjectionPreservesObservedMetadata': 'Failed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.MissingAccountAndInvalidTenantRemainMissing': 'Passed',
 'Authentication.Windows.Scenarios.MsalAdapterScenarios.RejectedCustomUiCannotReturnAuthorizationUri': 'Failed',
 'Authentication.Windows.Scenarios.ManagedTransportScenarios.ManagedUserAgentIsSingleStableAndForwardsCancellation': 'Failed'}
OWNED_HOST_RED = {
    'Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotCreateOwnedUi': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.ForbiddenInteractionDoesNotCreateOwnedUi': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.MissingPresentationPreventsInteraction': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.ReadyParentCarriesAdmittedBranding': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CreationFailurePreventsInteractiveAcquisition': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.OriginalCancellationBeforeCreationWins': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringCreationRejectsLateParent': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CloseDuringCreationCannotReopenHost': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.ClosedHostCannotReopen': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.InternalCloseDoesNotCancelCaller': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CompletionWaitsForActualUiThreadExit': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CancelButtonStopsPendingAuthentication': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CaptionCloseStopsPendingAuthentication': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.EscapeStopsPendingAuthentication': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.PostReadinessCallbackFaultIsContained': 'Failed',
}
# The accepted H-green result precedes the credential-free local-provider selection.
LOCAL_PROVIDER_PRIOR_START = "10fc85a750e5494f7844332154b859ef97181ce6139fadae37fa2c06c90ee9e2"
LOCAL_PROVIDER_PRIOR_FINAL = "2043defeed2bd068a5e9cba888c3b08b85aad4b6e40dc868216900d4e94dac41"
LOCAL_PROVIDER_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "ec31b39b0cec4865cd7c0b4c8012b989ae6b0615b79938b9640a78c6cccde162",
    "Invoke-WindowsValidation.ps1": "a63d1715179171227c9df3875bd538ba744568954809d40202cf0a4d420f0635",
}
LOCAL_PROVIDER_RED = {
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.ConstructionDoesNotObserveHostOrInitializeProvider': 'Passed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.PrecancelledRequestStopsBeforeHostAdmission': 'Passed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.RejectedHostPreventsInitializationAndOwnedUi': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.AdmittedHostAllowsOneSelectedAccountSilentResult': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringAdmissionPreventsInitialization': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.OriginalCancellationWinsOverAdmissionRejection': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringInitializationPreventsDiscovery': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnavailableInitializationPreventsDiscoveryAndOwnedUi': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnexpectedInitializationFaultStaysInternalFailure': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnexpectedHostObservationFaultStaysInternalFailure': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.LostEligibilityBeforeSilentPreventsAcquisition': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.LostEligibilityAfterReadinessPreventsInteractionAndClosesHost': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringVolatileRecheckPreventsNextEffect': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.EligibleInteractiveContinuationUsesOriginalRequestAndOneParent': 'Failed',
    'Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.NoninteractivePermissionDoesNotOpenHostAfterSilentChallenge': 'Failed',
}

# Completed local-provider green precedes the synthetic host-fact selection.
HOST_ADMISSION_PRIOR_START = "701478479cf1bf1c4fa5dbfdce4d02d5facd015b067a825785b51515d27408dd"
HOST_ADMISSION_PRIOR_FINAL = "ac1b287b7dafbb2082e173efad20585f062731b922ff593c33410184740c1456"
HOST_ADMISSION_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "0e01a22ee8e63720f54ad6525976d1b282656f33a8682919fd316b7ff4633d39",
    "Invoke-WindowsValidation.ps1": "dc4019e3ba3f62cafda1222f4468f270cf1b935c7ec7ca761f0b36c2a290a3ce",
}
HOST_ADMISSION_RED = {
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ConstructionDoesNotObserveLocalState': 'Passed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.PrecancelledRequestDoesNotObserveLocalState': 'Passed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.OrdinaryInteractiveLogonKindsPermitSelectedAccountAcquisition': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.UnsupportedPlatformStopsBeforeWindowsObservations': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ServerOrUnobservableProductPreventsInitialization': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ImpersonationOrUnknownThreadIdentityPreventsInitialization': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.MissingOrInvalidOwnLogonPreventsInitialization': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ServiceIdentitiesPrecludeAccountDiscovery': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.NoninteractiveAndAlternateCredentialLogonKindsAreRejected': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.HiddenWindowStationPreventsInitialization': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.MissingOrDifferentWindowStationUserPreventsInitialization': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.InactiveOrUnobservableSessionPreventsInitialization': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.NoninputOrUnobservableDesktopPreventsInitialization': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.CancellationAfterAnyObservationStopsFurtherQueriesAndInitialization': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.OriginalCancellationWinsWhenAnObservationThrows': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.UnexpectedObservationFaultRemainsSanitizedInternalFailure': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.SessionLossBeforeSilentAcquisitionPreventsItsEffect': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ImpersonationBeforeSilentAcquisitionPreventsItsEffect': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.InputDesktopLossAfterReadinessPreventsInteractionAndClosesParent': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.CancellationDuringVolatileObservationPreventsAcquisition': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.EachProviderEffectHasFreshVolatileObservations': 'Failed',
    'Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ObservationsRunOnTheCallingThreadWithOriginalCancellation': 'Failed',
}

UI_ADMISSION_PRIOR_START = "b04688941e504d594947544e26f12d87c99d7de0bbd86b280e17c1ee20e63f68"
UI_ADMISSION_PRIOR_FINAL = "ba41f9bbcee348c694f187d8b966fb097baea450c938cc866e3bf77e6a73cd58"
UI_ADMISSION_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "0747221d12d689ca80b9022ffcfa6cd23a5584165398482cdd1b5bbc0bed3c5b",
    "Invoke-WindowsValidation.ps1": "3263b10d1c478c723a6c9c0b3d5926d47a5cdba5bca1da5184b132543596daeb",
}
UI_ADMISSION_RED = {
    'Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotCreateOwnedUi': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.ForbiddenInteractionDoesNotCreateOwnedUi': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.MissingPresentationPreventsInteraction': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.ReadyParentCarriesAdmittedBranding': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CreationFailurePreventsInteractiveAcquisition': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.OriginalCancellationBeforeCreationWins': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringCreationRejectsLateParent': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CloseDuringCreationCannotReopenHost': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.ClosedHostCannotReopen': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.InternalCloseDoesNotCancelCaller': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CompletionWaitsForActualUiThreadExit': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CancelButtonStopsPendingAuthentication': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CaptionCloseStopsPendingAuthentication': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.EscapeStopsPendingAuthentication': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.PostReadinessCallbackFaultIsContained': 'Passed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.UiRejectionBeforeCreationPreventsParentAndAcquisition': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.UiRejectionBeforeShowingWithholdsParentAndAcquisition': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.UiRechecksUseOriginalTokenOnTheOwnedStaThread': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringUiRecheckPreventsAcquisition (1)': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringUiRecheckPreventsAcquisition (2)': 'Failed',
    'Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotInspectTheOwnedUiThread': 'Passed',
}

TEST_FILTERS = {'cli': 'FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.ExplicitFilePreservesSelectedProfileAndRequest|FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.FileSizeLimitAppliesBeforeAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.ReplacingFileAfterAdmissionCannotChangeTheInFlightProfile|FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.UnreadableOrInvalidFileStopsBeforeProviderConstruction|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.RootHelpCompletesWithoutAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.MalformedAuthenticationReturnsTheBootstrapFailure|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.SelectedRequestReturnsOneSuccessDespiteBrokenDiagnostics|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.FlaggedRegularFileStopsBeforeProfileAndProvider|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.AlreadyClosedLifetimePipeCancelsBeforeAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.WriterClosureRejectsLateSuccessAndEndsTheProcess|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.ClosedStdinWithoutTheFlagDoesNotCancel|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.LifetimePipePayloadIsIgnoredAndClosureStillCancels|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.DeadlineEndsUncooperativeWorkWithinTheProcessBound|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.BrokenResultReaderEndsWithTransportFailure|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.UndrainedResultPipeCannotKeepTheProcessAlive|FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.BlockedDiagnosticsDoNotChangeTheAuthenticationResultOrKeepTheProcessAlive',
 'adapter': 'FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ConsentRequirementHonorsInteractionPermission|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.SilentClaimsReachOneContinuationAndSecondChallengeStops|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.AccessDeniedWinsOverUiRequiredAndRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.Structured65004WinsOverRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.DenialTextAndNativeCodeDoNotImplyEntraDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.DuplicateErrorCodesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.NonNumericErrorCodesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.MalformedOrOverBudgetBodiesDoNotCreateDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ProviderUserCancellationRemainsCancelled|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalCancellationWinsOverDenial|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.OriginalDeadlineWinsLateProviderCancellation|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.HttpTimeoutDoesNotConsumeRequestDeadline|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RetryableProviderStopsWithoutApplicationRetry|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RecognizedNetworkErrorStopsWithoutRetry|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UnknownProviderConfigurationStaysInternal|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UnexplainedCancellationStaysInternal|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.UserMismatchWinsOverRetryHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.ResultProjectionPreservesObservedMetadata|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.MissingAccountAndInvalidTenantRemainMissing|FullyQualifiedName=Authentication.Windows.Scenarios.MsalAdapterScenarios.RejectedCustomUiCannotReturnAuthorizationUri|FullyQualifiedName=Authentication.Windows.Scenarios.ManagedTransportScenarios.ManagedUserAgentIsSingleStableAndForwardsCancellation'}

TEST_FILTERS["owned-host"] = 'FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ForbiddenInteractionDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.MissingPresentationPreventsInteraction|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ReadyParentCarriesAdmittedBranding|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CreationFailurePreventsInteractiveAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.OriginalCancellationBeforeCreationWins|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringCreationRejectsLateParent|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CloseDuringCreationCannotReopenHost|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ClosedHostCannotReopen|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.InternalCloseDoesNotCancelCaller|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CompletionWaitsForActualUiThreadExit|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancelButtonStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CaptionCloseStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.EscapeStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.PostReadinessCallbackFaultIsContained'


TEST_FILTERS["local-provider"] = 'FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.ConstructionDoesNotObserveHostOrInitializeProvider|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.PrecancelledRequestStopsBeforeHostAdmission|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.RejectedHostPreventsInitializationAndOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.AdmittedHostAllowsOneSelectedAccountSilentResult|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringAdmissionPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.OriginalCancellationWinsOverAdmissionRejection|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringInitializationPreventsDiscovery|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnavailableInitializationPreventsDiscoveryAndOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnexpectedInitializationFaultStaysInternalFailure|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.UnexpectedHostObservationFaultStaysInternalFailure|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.LostEligibilityBeforeSilentPreventsAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.LostEligibilityAfterReadinessPreventsInteractionAndClosesHost|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.CancellationDuringVolatileRecheckPreventsNextEffect|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.EligibleInteractiveContinuationUsesOriginalRequestAndOneParent|FullyQualifiedName=Authentication.Windows.Scenarios.LocalProviderAdmissionScenarios.NoninteractivePermissionDoesNotOpenHostAfterSilentChallenge'


TEST_FILTERS["host-admission"] = 'FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ConstructionDoesNotObserveLocalState|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.PrecancelledRequestDoesNotObserveLocalState|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.OrdinaryInteractiveLogonKindsPermitSelectedAccountAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.UnsupportedPlatformStopsBeforeWindowsObservations|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ServerOrUnobservableProductPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ImpersonationOrUnknownThreadIdentityPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.MissingOrInvalidOwnLogonPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ServiceIdentitiesPrecludeAccountDiscovery|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.NoninteractiveAndAlternateCredentialLogonKindsAreRejected|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.HiddenWindowStationPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.MissingOrDifferentWindowStationUserPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.InactiveOrUnobservableSessionPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.NoninputOrUnobservableDesktopPreventsInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.CancellationAfterAnyObservationStopsFurtherQueriesAndInitialization|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.OriginalCancellationWinsWhenAnObservationThrows|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.UnexpectedObservationFaultRemainsSanitizedInternalFailure|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.SessionLossBeforeSilentAcquisitionPreventsItsEffect|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ImpersonationBeforeSilentAcquisitionPreventsItsEffect|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.InputDesktopLossAfterReadinessPreventsInteractionAndClosesParent|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.CancellationDuringVolatileObservationPreventsAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.EachProviderEffectHasFreshVolatileObservations|FullyQualifiedName=Authentication.Windows.Scenarios.WindowsHostAdmissionScenarios.ObservationsRunOnTheCallingThreadWithOriginalCancellation'


TEST_FILTERS["ui-admission"] = 'FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ForbiddenInteractionDoesNotCreateOwnedUi|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.MissingPresentationPreventsInteraction|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ReadyParentCarriesAdmittedBranding|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CreationFailurePreventsInteractiveAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.OriginalCancellationBeforeCreationWins|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringCreationRejectsLateParent|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CloseDuringCreationCannotReopenHost|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.ClosedHostCannotReopen|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.InternalCloseDoesNotCancelCaller|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CompletionWaitsForActualUiThreadExit|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancelButtonStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CaptionCloseStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.EscapeStopsPendingAuthentication|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.PostReadinessCallbackFaultIsContained|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.UiRejectionBeforeCreationPreventsParentAndAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.UiRejectionBeforeShowingWithholdsParentAndAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.UiRechecksUseOriginalTokenOnTheOwnedStaThread|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.CancellationDuringUiRecheckPreventsAcquisition|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedHostScenarios.SilentSuccessDoesNotInspectTheOwnedUiThread'

OWNED_PROCESS_PRIOR_START = "6e319296ad021197545950ab6805d578df817a4b5e339e65f9eeaf4c429b08df"
OWNED_PROCESS_PRIOR_FINAL = "632955ce8c14d50aff82b018d94e11d3d9994765d922d744fcce0829ed46699f"
OWNED_PROCESS_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "46459e4cf476c22e28432fa1397026a4b1b56f8580119e685db120dc6c7b4e55",
    "Invoke-WindowsValidation.ps1": "454a59e9d5fae0993c8842f50c11701c0311c5999830bea177f5cee130f0c104",
}
OWNED_PROCESS_CASES = {'NormalOwnedClosurePreservesSuccessAndDrains': 'host-success', 'LocalCancellationSuppressesSuccessBeforeDelayedNotification': 'host-cancel', 'LocalHostFaultSuppressesSuccessBeforeDelayedNotification': 'host-fault', 'CancellationDuringCreationSurvivesClosureFailure': 'host-create-cancel', 'OrdinaryCreationFailureRemainsMechanismUnavailable': 'host-create-failure', 'CleanupFaultAfterNormalClosureSuppressesUncommittedSuccess': 'host-fault-before-commit', 'CleanupFaultAfterCommitCannotReplaceTheResult': 'host-fault-after-commit', 'ProcessWaitsForTheActualOwnedThreadExit': 'host-ui-join', 'ProcessWaitsForTheOutgoingOwnedCallback': 'host-callback-drain', 'NormalClosureArmsTheBoundBeforeCoreTerminalSelection': 'host-close-stall'}
OWNED_PROCESS_RED = {
    "Authentication.Windows.Scenarios.OwnedProcessScenarios." + name:
        "Passed" if child in ("host-success", "host-create-failure") else "Failed"
    for name, child in OWNED_PROCESS_CASES.items()
}
TEST_FILTERS["owned-process"] = 'FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.NormalOwnedClosurePreservesSuccessAndDrains|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.LocalCancellationSuppressesSuccessBeforeDelayedNotification|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.LocalHostFaultSuppressesSuccessBeforeDelayedNotification|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.CancellationDuringCreationSurvivesClosureFailure|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.OrdinaryCreationFailureRemainsMechanismUnavailable|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.CleanupFaultAfterNormalClosureSuppressesUncommittedSuccess|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.CleanupFaultAfterCommitCannotReplaceTheResult|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.ProcessWaitsForTheActualOwnedThreadExit|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.ProcessWaitsForTheOutgoingOwnedCallback|FullyQualifiedName=Authentication.Windows.Scenarios.OwnedProcessScenarios.NormalClosureArmsTheBoundBeforeCoreTerminalSelection'


MSAL_CONSTRUCTION_PRIOR_START = "5e3e684f790c30eed91f4a26829f5cb4cedbe63303d5003ef0eda09cc5f18985"
MSAL_CONSTRUCTION_PRIOR_FINAL = "6c0d567b62b8e3f856b3dd67d7a1cee0d4c93bdc458a1f5a6487a80a81b6023c"
MSAL_CONSTRUCTION_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "c0477077eff68182bae6f6b7d9aced6e56d3e3864d15bcd2b7ea25e8c75924e8",
    "Invoke-WindowsValidation.ps1": "7bbac1e2f2688d9057258c4ad7b67493c8f78926aa297387c9f2e410d4eb212f",
}
MSAL_CONSTRUCTION_CASES = (
    'Authentication.Windows.Scenarios.MsalConstructionScenarios.OrdinaryProfileConstructsCommonApplication',
    'Authentication.Windows.Scenarios.MsalConstructionScenarios.LegacyProfileConstructsOrganizationsApplication',
    'Authentication.Windows.Scenarios.MsalConstructionScenarios.ExactTenantProfileConstructsRestrictedApplication',
    'Authentication.Windows.Scenarios.MsalConstructionScenarios.OriginalCancellationPreventsApplicationConstruction',
)
TEST_FILTERS["msal-construction"] = 'FullyQualifiedName=Authentication.Windows.Scenarios.MsalConstructionScenarios.OrdinaryProfileConstructsCommonApplication|FullyQualifiedName=Authentication.Windows.Scenarios.MsalConstructionScenarios.LegacyProfileConstructsOrganizationsApplication|FullyQualifiedName=Authentication.Windows.Scenarios.MsalConstructionScenarios.ExactTenantProfileConstructsRestrictedApplication|FullyQualifiedName=Authentication.Windows.Scenarios.MsalConstructionScenarios.OriginalCancellationPreventsApplicationConstruction'

MSAL_COMPOSITION_PRIOR_START = "5d1fd49bef654fdfd4dd5773c7f766115549e99dee348b0ad7638fa25f1274e4"
MSAL_COMPOSITION_PRIOR_FINAL = "06c6a4077e3272a6584f21ec35095d3f34f6e03b7de4ba406949acec4f1b37d9"
MSAL_COMPOSITION_PREVIOUS_CONTROLLERS = {'run_windows.py': 'd1c7f31e6c68cf11520c998cbb3af78dba277484ea90ce07dca23a1f67167271', 'Invoke-WindowsValidation.ps1': 'aaab817f2b56092619b6af0a0af6c08f9e187986c149d3a9fcf3fdf7c1c9c506'}
MSAL_COMPOSITION_CASES = (
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.OrdinaryMultitenantProfileUsesCommon',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.FixedWorkProfileUsesItsTenant',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.ExplicitWorkTenantOverridesCommon',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.LegacyPersonalAccountUsesTheTransferTenant',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.LegacyWorkAccountRetainsOrganizations',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.ExplicitResourceTenantWinsOverLegacyPersonalRouting',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.SilentClaimsContinueWithTheSameAccountAndNoCompetingHint',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.NoVisibleMatchUsesOnlyTheRequestedLoginHint',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.ASecondChallengeStopsAndDoesNotExposeProviderDetails',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.DiscoveryFailureUsesTheSameSafeProviderClassification',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.ProviderInitializationFailureUsesTheSameSafeClassification',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.CancellationDuringLoaderSetupPreventsSessionConstruction',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.FailedLoaderSetupPreventsSessionConstruction',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.CancellationDuringSessionConstructionPreventsDiscovery',
    'Authentication.Windows.Scenarios.MsalCompositionScenarios.OriginalCancellationWinsOverADiscoveryFailure',
    'Authentication.Windows.Scenarios.MsalHttpOwnershipScenarios.OneOwnedClientSurvivesOperationsUntilCancellationAndDrain',
)
TEST_FILTERS["msal-composition"] = 'FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.OrdinaryMultitenantProfileUsesCommon|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.FixedWorkProfileUsesItsTenant|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.ExplicitWorkTenantOverridesCommon|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.LegacyPersonalAccountUsesTheTransferTenant|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.LegacyWorkAccountRetainsOrganizations|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.ExplicitResourceTenantWinsOverLegacyPersonalRouting|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.SilentClaimsContinueWithTheSameAccountAndNoCompetingHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.NoVisibleMatchUsesOnlyTheRequestedLoginHint|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.ASecondChallengeStopsAndDoesNotExposeProviderDetails|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.DiscoveryFailureUsesTheSameSafeProviderClassification|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.ProviderInitializationFailureUsesTheSameSafeClassification|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.CancellationDuringLoaderSetupPreventsSessionConstruction|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.FailedLoaderSetupPreventsSessionConstruction|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.CancellationDuringSessionConstructionPreventsDiscovery|FullyQualifiedName=Authentication.Windows.Scenarios.MsalCompositionScenarios.OriginalCancellationWinsOverADiscoveryFailure|FullyQualifiedName=Authentication.Windows.Scenarios.MsalHttpOwnershipScenarios.OneOwnedClientSurvivesOperationsUntilCancellationAndDrain'


# Bind the completed preceding construction action.
# Its accepted review and the new protocol remain prerequisites for promotion.
DEFAULT_HTTP_PRIOR_ACTION = 49
DEFAULT_HTTP_PRIOR_START = "746dffeac49b23fa9b061522e25a8f88afe14d4c802372615f62c2b3fbfbdea2"
DEFAULT_HTTP_PRIOR_FINAL = "75a3b87ffe77ca8f5935e6628e7e5604e48ce392f68ac62a48dc0c4515703e8f"
DEFAULT_HTTP_PRIOR_PROTOCOL = "ae53bc2448c2e24d3df0eac61daf5d6bd143a4bc"
DEFAULT_HTTP_PREVIOUS_CONTROLLERS = {
    "run_windows.py": "64ca92f7778e8c80d609cff11ff577a5cfc6c1bed313c70ac14c5c22f7eda49f",
    "Invoke-WindowsValidation.ps1": "15670d2705e4f8921affe7ac030edb50815503c7aeb2ea7956772ee938cc278b",
}
DEFAULT_HTTP_CLASS = 'Authentication.Windows.Scenarios.DefaultHttpCompositionScenarios'
DEFAULT_HTTP_CASES = {'SharedDefaultHttpOwnershipSurvivesCancellationUntilDrain': 'default-http-cancel-drain', 'SharedDefaultHttpDisposalStallRetainsTheProcessWatchdog': 'default-http-dispose-stall'}
TEST_FILTERS["default-http-composition"] = 'FullyQualifiedName=Authentication.Windows.Scenarios.DefaultHttpCompositionScenarios.SharedDefaultHttpOwnershipSurvivesCancellationUntilDrain|FullyQualifiedName=Authentication.Windows.Scenarios.DefaultHttpCompositionScenarios.SharedDefaultHttpDisposalStallRetainsTheProcessWatchdog'


DEFAULT_HTTP_COMMON_MARKERS = ('entered', 'provider-created', 'http-owner-created', 'loader-entered', 'session-created', 'ui-thread-started', 'hidden-parent-created', 'provider-ready', 'http-send-entered', 'host-closing', 'native-cleanup-completed', 'before-commit', 'after-commit', 'drain-boundary')
DEFAULT_HTTP_CANCEL_MARKERS = ('host-callback-pending', 'http-cancel-observed', 'provider-callback-pending', 'host-callback-forwarded', 'pending-drain-observed', 'drain-release-observed')
DEFAULT_HTTP_OTHER_MARKERS = ('http-dispose-entered', 'http-dispose-completed', 'process-returned', 'premature-http-disposal', 'cancellation-order-invalid', 'candidate-returned', 'dispose-stall-entered')


def validate_windows_reservation_pair(started, peer, link, final, start_hash, final_hash, evidence):
    """Bind the initial WSL admission to its verified Windows execution copy."""
    if evidence.get("started.json") != start_hash or evidence.get("windows-result.json") != final_hash or \
            link != {"sha256": start_hash} or final.get("reservationSha256") != start_hash:
        raise ValueError("Missing or inconsistent Windows reservation link")
    extensions = {"fileSha256", "toolSha256"}
    if started.get("action") != "bootstrap":
        extensions.update(("helperPath", "helperSha256"))
    if not extensions <= peer.keys() or extensions & started.keys() or \
            {key: value for key, value in peer.items() if key not in extensions} != started:
        raise ValueError("WSL and Windows reservation copies disagree")


def verify_windows_reservation_pair(action, windows_action, result, started):
    paths = (windows_action / "started.json", windows_action / "windows-result.json", action / "windows-input.json")
    for path in paths:
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("Linked Windows reservation evidence")

    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate Windows reservation field")
            value[key] = item
        return value

    peer, final, link = (json.loads(path.read_text(), object_pairs_hook=unique) for path in paths)
    validate_windows_reservation_pair(started, peer, link, final,
                                     digest(paths[0]), digest(paths[1]), result["evidence"])
    if int(action.name) >= 22 and started.get("action") == "test" and \
            (started.get("testSuite") in ("ui-admission", "owned-process", "default-http-composition") or
             started.get("testSuite") == "owned-host" and started.get("expected") == "green"):
        evidence = result["evidence"]
        ready_path = windows_action / "attendance-ready.json"
        released_path = windows_action / "attendance-released.json"
        for path in (ready_path, released_path):
            if any(part.is_symlink() for part in (path, *path.parents)) or path.stat().st_size > 8192:
                raise ValueError("Invalid retained attendance receipt")
        ready = json.loads(ready_path.read_text(), object_pairs_hook=unique)
        released = json.loads(released_path.read_text(), object_pairs_hook=unique)
        ready_hash, released_hash = digest(ready_path), digest(released_path)
        marker_name = "attendance-release-" + ready_hash
        wait_seconds = 1800 if int(action.name) <= 34 else ATTENDANCE_SECONDS
        if set(ready) != {"action", "reservationSha256", "waitSeconds", "invocationSha256",
                          "controllerSha256", "preparedUtc"} or ready["action"] != action.name or \
                ready["reservationSha256"] != digest(paths[0]) or type(ready["waitSeconds"]) is not int or \
                ready["waitSeconds"] != wait_seconds or ready["invocationSha256"] != evidence.get("invocation.json") or \
                ready["controllerSha256"] != evidence.get("controller.json") or \
                evidence.get("attendance-ready.json") != ready_hash or \
                evidence.get("attendance-released.json") != released_hash or \
                final.get("attendanceReadySha256") != ready_hash or \
                final.get("attendanceReleasedSha256") != released_hash or \
                set(released) != {"readySha256", "releaseName", "waitMilliseconds"} or \
                released["readySha256"] != ready_hash or released["releaseName"] != marker_name or \
                type(released["waitMilliseconds"]) is not int or not 0 <= released["waitMilliseconds"] < wait_seconds * 1000 or \
                evidence.get(marker_name) != hashlib.sha256(b"").hexdigest() or "cancel" in evidence or \
                [name for name in evidence if name.startswith("attendance-release-")] != [marker_name]:
            raise ValueError("Retained attendance binding changed")


def windows_process_reservation(number, started):
    """Preserve historical full batches and require explicit new finite selections."""
    action = started.get("action")
    if action not in ("bootstrap", "restore", "build", "test"):
        raise ValueError("Unknown Windows action allocation")
    if number <= 14:
        if "testSuite" in started:
            raise ValueError("Historical Windows selection changed")
        required = 12 if number > 9 and action == "test" else 0
    else:
        if "testSuite" not in started:
            raise ValueError("Missing Windows selection")
        suite = started["testSuite"]
        if started.get("expected") not in ("red", "green") or (action != "test" and started["expected"] != "green"):
            raise ValueError("Unexpected Windows result expectation")
        if action == "test":
            if suite not in ("cli", "adapter", "owned-host", "local-provider", "host-admission", "ui-admission", "owned-process", "msal-composition", "msal-construction", "default-http-composition") or \
                    (suite == "owned-host" and number <= 18) or \
                    (suite == "local-provider" and number <= 24) or \
                    (suite == "host-admission" and number <= 28) or \
                    (suite == "ui-admission" and number <= 32) or \
                    (suite == "owned-process" and number <= 38) or \
                    (suite == "msal-composition" and number <= 42) or \
                    (suite == "msal-construction" and number <= 46) or \
                    (suite == "default-http-composition" and
                     (type(DEFAULT_HTTP_PRIOR_ACTION) is not int or number <= DEFAULT_HTTP_PRIOR_ACTION + 1)):
                raise ValueError("Unknown Windows test selection")
            required = (12 if suite == "cli" else 10 if suite == "owned-process" else
                        2 if suite == "default-http-composition" else 0)
        else:
            if suite is not None:
                raise ValueError("Non-test Windows selection")
            required = 0
    reserved = started.get("reservedProcessScenarios", 0 if number <= 9 else None)
    if type(reserved) is not int or reserved != required:
        raise ValueError("Unrecoverable Windows process reservation")
    return reserved


def selected_cases(suite, expected):
    if suite == "default-http-composition":
        return {DEFAULT_HTTP_CLASS + "." + name: "Failed" if expected == "red" else "Passed"
                for name in DEFAULT_HTTP_CASES}
    if suite == "msal-construction":
        return {name: "Failed" if expected == "red" else "Passed"
                for name in MSAL_CONSTRUCTION_CASES}
    if suite == "msal-composition":
        return {name: "Failed" if expected == "red" else "Passed"
                for name in MSAL_COMPOSITION_CASES}
    if suite == "owned-process":
        return {name: outcome if expected == "red" else "Passed"
                for name, outcome in OWNED_PROCESS_RED.items()}
    if suite == "ui-admission":
        return {name: outcome if expected == "red" else "Passed"
                for name, outcome in UI_ADMISSION_RED.items()}
    if suite == "host-admission":
        return {name: outcome if expected == "red" else "Passed"
                for name, outcome in HOST_ADMISSION_RED.items()}
    if suite == "local-provider":
        return {name: outcome if expected == "red" else "Passed"
                for name, outcome in LOCAL_PROVIDER_RED.items()}
    if suite == "owned-host":
        return {name: outcome if expected == "red" else "Passed"
                for name, outcome in OWNED_HOST_RED.items()}
    if suite == "adapter":
        return {name: outcome if expected == "red" else "Passed"
                for name, outcome in ADAPTER_RED.items()}
    if suite != "cli":
        raise ValueError("Unknown Windows test selection")
    prefix = "Authentication.Windows.Scenarios."
    cases = {prefix + "ProfileFileScenarios." + name: "Passed" for name in FILE_CASES}
    cases.update({prefix + "ProcessScenarios." + name: "Failed" if expected == "red" else "Passed"
                  for name in PROCESS_CASES})
    return cases


def validate_selected_report(report, suite, expected):
    """Bind every expanded result to its class/name definition and full counters."""
    cases = selected_cases(suite, expected)
    required = {"total": len(cases), "executed": len(cases),
                "passed": sum(value == "Passed" for value in cases.values()),
                "failed": sum(value == "Failed" for value in cases.values())}
    required.update({name: 0 for name in (
        "error", "timeout", "aborted", "inconclusive", "passedButRunAborted", "notRunnable",
        "notExecuted", "disconnected", "warning", "completed", "inProgress", "pending")})
    counters = report.findall(".//{*}Counters")
    if len(counters) != 1 or counters[0].attrib != {key: str(value) for key, value in required.items()}:
        raise ValueError("Unexpected admitted case counts")
    definitions = report.findall(".//{*}UnitTest")
    identities = {}
    for definition in definitions:
        identity = definition.attrib["id"]
        methods = definition.findall("{*}TestMethod")
        if identity in identities or len(methods) != 1:
            raise ValueError("Duplicate or ambiguous test definition")
        method = methods[0]
        if definition.attrib["name"] != method.attrib["name"]:
            raise ValueError("Test definition name changed")
        identities[identity] = (method.attrib["className"] + "." + method.attrib["name"],
                                method.attrib["name"])
    results = report.findall(".//{*}UnitTestResult")
    observed, result_ids = {}, set()
    for node in results:
        identity = node.attrib["testId"]
        if identity in result_ids or identity not in identities:
            raise ValueError("Duplicate or undefined test result")
        result_ids.add(identity)
        qualified, name = identities[identity]
        if node.attrib["testName"] != name or qualified in observed:
            raise ValueError("Ambiguous expanded test result")
        observed[qualified] = node.attrib["outcome"]
    if len(definitions) != len(cases) or result_ids != set(identities) or observed != cases:
        raise ValueError("Unexpected case classes, names or dispositions")
    return counters[0].attrib


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
    result = {"subject/global.json": digest(subject / "global.json"), "nuget.config": digest(ROOT / "nuget.config"),
              "subject/Windows.slnx": digest(subject / PROJECT)}
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
        if any((ROOT / "actions" / action.name / "temp" / marker).exists()
               for marker in ("owned-host-safety-stop.json", "process-safety-stop.json")):
            raise ValueError("Owned fixture safety stop forbids continuation")
        if action.name == "0002":
            verify_disposed_windows_preparation(action)
        elif action.name == "0003":
            direct(action)
            if {path.name for path in action.iterdir()} != set(DISPOSED_WINDOWS_RESTORE) or any(
                digest(action / name) != expected for name, expected in DISPOSED_WINDOWS_RESTORE.items()
            ):
                raise ValueError("Disposed Windows restore receipt changed")
        elif action.name == "0006":
            verify_disposed_windows_test(action)
        elif action.name == "0022":
            verify_disposed_windows_attendance(action, ROOT / "actions" / action.name)
        elif action.name == "0033":
            verify_disposed_windows_attendance(
                action, ROOT / "actions" / action.name, DISPOSED_UI_ATTENDANCE)
        elif action.name == "0034":
            verify_disposed_windows_attendance(
                action, ROOT / "actions" / action.name, DISPOSED_UI_ATTENDANCE_0034)
        elif action.name == "0039":
            verify_disposed_owned_process_red(action, ROOT / "actions" / action.name)
        elif result.get("continuation_allowed") is not True or result.get("quiescent") is not True:
            raise ValueError("Unresolved Windows action")
        for name, expected in result["evidence"].items():
            if digest(ROOT / "actions" / action.name / name) != expected:
                raise ValueError("Windows evidence changed")
        started = read(action / "started.json")
        if action.name not in ("0002", "0003", "0006", "0022", "0033", "0034"):
            verify_windows_reservation_pair(action, ROOT / "actions" / action.name, result, started)
        windows.append((action, started, result))
    return linux, windows


def verify_disposed_owned_process_red(action, failed):
    """Recognize only the accepted failed 0039 evidence, never a replacement result."""
    for root in (action, failed):
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ValueError("Linked disposed owned-process evidence")
    if action.name != "0039" or {path.name for path in action.iterdir()} != set(DISPOSED_OWNED_PROCESS_RED) or any(
        not (action / name).is_file() or (action / name).is_symlink() or digest(action / name) != expected
        for name, expected in DISPOSED_OWNED_PROCESS_RED.items()
    ):
        raise ValueError("Disposed owned-process receipts changed")
    evidence = json.loads((action / "result.json").read_text())["evidence"]
    paths = list(failed.rglob("*"))
    directories = sorted(str(path.relative_to(failed)) for path in paths if path.is_dir())
    directory_hash = hashlib.sha256(json.dumps(directories, separators=(",", ":")).encode()).hexdigest()
    if directory_hash != "0ee100b271ff3f109ea874d8f2a3fde3c20741f249898d22ca62c2b56519d2aa" or \
            {str(path.relative_to(failed)) for path in paths if path.is_file()} != set(evidence):
        raise ValueError("Disposed owned-process evidence boundary changed")
    for path in paths:
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("Invalid disposed owned-process evidence entry")
        if path.is_file() and digest(path) != evidence[str(path.relative_to(failed))]:
            raise ValueError("Disposed owned-process evidence changed")


def verify_disposed_windows_attendance(action, failed, receipts=DISPOSED_WINDOWS_ATTENDANCE):
    """Preserve an exactly disposed expired wait and its empty Job evidence."""
    for root in (action, failed):
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ValueError("Linked disposed attendance evidence")
    if {path.name for path in action.iterdir()} != set(receipts) or any(
        (action / name).is_symlink() or not (action / name).is_file() or
        digest(action / name) != expected
        for name, expected in receipts.items()
    ):
        raise ValueError("Disposed attendance receipt changed")
    evidence = json.loads((action / "result.json").read_text())["evidence"]
    directories = {"home", "home/local", "home/roaming", "temp", "results", "empty-program-files"}
    paths = list(failed.rglob("*"))
    if {str(path.relative_to(failed)) for path in paths} != directories | set(evidence):
        raise ValueError("Disposed attendance boundary changed")
    for path in paths:
        name = str(path.relative_to(failed))
        if path.is_symlink() or (name in directories and not path.is_dir()):
            raise ValueError("Disposed attendance directory changed")
        if name not in directories and (not path.is_file() or digest(path) != evidence[name]):
            raise ValueError("Disposed attendance evidence changed")


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


def verify_disposed_windows_test(action):
    """Retain only the exact generated-name stop and its empty pre-subject boundary."""
    direct(action)
    if {path.name for path in action.iterdir()} != set(DISPOSED_WINDOWS_TEST) or any(
        digest(action / name) != expected for name, expected in DISPOSED_WINDOWS_TEST.items()
    ):
        raise ValueError("Disposed Windows test receipt changed")
    failed = ROOT / "actions/0006"
    direct(failed)
    directories = {"home", "home/local", "home/roaming", "temp", "results", "empty-program-files"}
    evidence = read(action / "result.json")["evidence"]
    paths = list(failed.rglob("*"))
    if {str(path.relative_to(failed)) for path in paths} != directories | set(evidence):
        raise ValueError("Disposed Windows test boundary changed")
    for path in paths:
        direct(path)
        name = str(path.relative_to(failed))
        if name in directories:
            if not path.is_dir():
                raise ValueError("Disposed Windows test directory changed")
        elif not path.is_file() or digest(path) != evidence[name]:
            raise ValueError("Disposed Windows test evidence changed")


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
    for filename, (_, _, content_hash) in PROCESS_ARCHIVES.items():
        # Package IDs contain dots; derive the finite reviewed cache directory.
        match = re.fullmatch(r"(.+)\.([0-9]+\.[0-9]+\.[0-9]+)\.nupkg", filename)
        name, version = match.groups()
        archives[filename] = (prior / "feed" / filename, prior / "packages" / name / version, content_hash)
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


def installed_packs():
    """Bind installed targeting/apphost payloads to retained public archives."""
    tools = dict(TOOLS)
    donor = Path("/mnt/c/Temp/azureauth-native-aot-diagnostics/round-05/feed")
    for name, (version, size, expected, prefixes) in INSTALLED_PACKS.items():
        archive = donor / f"{name.lower()}.{version}.nupkg"
        if archive.stat().st_size != size or digest(archive, "sha512") != expected:
            raise ValueError("Installed-pack provenance changed")
        base = Path("/mnt/c/Program Files/dotnet/packs") / name / version
        admitted = set()
        with zipfile.ZipFile(archive) as package:
            for item in package.infolist():
                relative = unquote(item.filename)
                if item.is_dir() or not any(relative.startswith(prefix) for prefix in prefixes):
                    continue
                actual = digest(base / relative)
                if actual != hashlib.sha256(package.read(item)).hexdigest():
                    raise ValueError("Installed pack differs from public payload")
                admitted.add(relative)
                tools[DOTNET + "packs\\" + name + "\\" + version + "\\" + relative.replace("/", "\\")] = actual
        if {str(item.relative_to(base)) for item in base.rglob("*") if item.is_file()} != admitted:
            raise ValueError("Installed pack file set changed")
    return tools


def process_evidence(action, expected, suite="cli"):
    """Validate completeness separately from the independent business-red review."""
    temporary = action / "temp"
    if (temporary / "process-safety-stop.json").exists():
        raise ValueError("Fixture safety stop forbids continuation")
    cases = set((DEFAULT_HTTP_CASES if suite == "default-http-composition" else
                 OWNED_PROCESS_CASES if suite == "owned-process" else PROCESS_CASES).values())
    if {path.name for path in temporary.glob("process-*")} != {"process-" + case for case in cases}:
        raise ValueError("Missing or unexpected process reservation")
    for case in sorted(cases):
        directory = temporary / ("process-" + case)
        reserved = read(directory / "reserved.json")
        started = read(directory / "started.json")
        receipt = read(directory / "result.json")
        if reserved.get("scenario") != case or started.get("pid", 0) <= 0 or \
                started.get("executable") != DOTNET + "dotnet.exe" or receipt.get("quiescent") is not True:
            raise ValueError("Incomplete child ownership/exit evidence")
        for name in ("stdout", "stderr"):
            count = (directory / (name + ".bin")).stat().st_size
            if count != receipt.get(name + "Bytes") or count > 524288:
                raise ValueError("Incomplete bounded child capture")
        if not isinstance(receipt.get("exitObservedTimestamp"), int) or receipt["exitObservedTimestamp"] <= 0:
            raise ValueError("Missing child exit observation")
        if case not in ("help", "malformed"):
            entered = int((directory / "entered").read_text())
            if entered <= 0 or receipt.get("entryTimestamp") != entered or \
                    receipt["exitObservedTimestamp"] < entered or receipt.get("timestampFrequency", 0) <= 0:
                raise ValueError("Missing managed-entry evidence")
        if suite == "owned-process":
            if receipt.get("forced") is not False or receipt.get("diagnosticPrefill") != 0 or \
                    receipt.get("bufferedOutput") != 0:
                raise ValueError("Owned-process capture or termination differs from its admission")
            output = (directory / "stdout.bin").read_bytes()
            if expected == "red":
                outcome = "mechanism_unavailable" if case in ("host-create-cancel", "host-create-failure") else "success"
                exit_code = 1 if outcome == "mechanism_unavailable" else 0
            else:
                outcome, exit_code = {
                    "host-success": ("success", 0),
                    "host-cancel": ("cancelled", 1),
                    "host-fault": ("internal_failure", 1),
                    "host-create-cancel": ("cancelled", 2),
                    "host-create-failure": ("mechanism_unavailable", 1),
                    "host-fault-before-commit": ("internal_failure", 2),
                    "host-fault-after-commit": ("success", 2),
                    "host-ui-join": ("success", 2),
                    "host-callback-drain": ("cancelled", 2),
                    "host-close-stall": (None, 2),
                }[case]
            indication = (b"" if outcome is None else b"Authentication request cancelled.\n"
                          if outcome == "cancelled" else b"Authentication request completed.\n")
            if not indication.startswith((directory / "stderr.bin").read_bytes()):
                raise ValueError("Owned-process diagnostics exceed the optional fixed indication")
            if receipt.get("exitCode") != exit_code:
                raise ValueError("Unexpected owned-process exit")
            if outcome is None:
                if output:
                    raise ValueError("Stalled pre-terminal closure unexpectedly produced output")
            else:
                if not output.endswith(b"\n") or output.count(b"\n") != 1 or output.startswith(b"\xef\xbb\xbf"):
                    raise ValueError("Owned-process output is not one UTF-8 protocol result")
                value = json.loads(output.decode("utf-8"), object_pairs_hook=pairs)
                if type(value.get("protocol")) is not int or value["protocol"] != 1 or value.get("outcome") != outcome:
                    raise ValueError("Unexpected owned-process result")
                if outcome == "success":
                    if value.get("accessToken") != "SYNTHETIC_PROCESS_SCENARIO_TOKEN" or \
                            value.get("accountEmail") != "personal@example.test" or value.get("interaction") != "interactive":
                        raise ValueError("Owned-process success differs from the synthetic candidate")
                elif set(value) != {"protocol", "outcome", "reason"} or value.get("reason") != outcome:
                    raise ValueError("Owned-process failure contains unexpected fields")
        if suite == "default-http-composition":
            default_http_evidence(directory, case, expected, receipt)
        if suite == "cli" and expected == "red":
            prefill = receipt.get("diagnosticPrefill")
            if type(prefill) is not int or (not 1 <= prefill <= 65536 if case == "blocked-diagnostics" else prefill != 0):
                raise ValueError("Unexpected synthetic diagnostic prefill")
            if receipt.get("forced") is not False or receipt.get("exitCode") != 2 or receipt["stdoutBytes"] != 0 or \
                    (directory / "stderr.bin").read_bytes() != b"D" * prefill:
                raise ValueError("Rejecting-stub red differs from admitted execution")


def default_http_evidence(directory, case, expected, receipt):
    """Project only fixed v2 witnesses; contextual RED acceptance remains separate."""
    cancellation = case == "default-http-cancel-drain"
    if case not in DEFAULT_HTTP_CASES.values() or expected not in ("red", "green"):
        raise ValueError("Unknown default HTTP evidence selection")
    required = set(DEFAULT_HTTP_COMMON_MARKERS)
    required.update(DEFAULT_HTTP_CANCEL_MARKERS if cancellation else ("candidate-returned",))
    if cancellation or expected == "red":
        required.add("process-returned")
    if expected == "green":
        required.update(("http-dispose-entered", "http-dispose-completed" if cancellation else "dispose-stall-entered"))
    whitelist = set(DEFAULT_HTTP_COMMON_MARKERS + DEFAULT_HTTP_CANCEL_MARKERS + DEFAULT_HTTP_OTHER_MARKERS)
    fixed_files = {"reserved.json", "started.json", "result.json", "profile.json", "stdout.bin", "stderr.bin"}
    controls = {"release-drain"} if cancellation else set()
    paths = {path.name: path for path in directory.iterdir()}
    if set(paths) - fixed_files - controls - whitelist or set(paths) != fixed_files | required | controls:
        raise ValueError("Default HTTP evidence has missing, foreign or failure-only files")
    for path in paths.values():
        direct(path)
        if not path.is_file():
            raise ValueError("Default HTTP evidence is not a fixed regular file")
    if cancellation and paths["release-drain"].stat().st_size != 0:
        raise ValueError("The fixed drain release must be empty")
    markers = {}
    for name in required:
        if paths[name].stat().st_size > 32:
            raise ValueError("Oversized default HTTP timestamp marker")
        raw = paths[name].read_bytes()
        if not re.fullmatch(rb"[1-9][0-9]*\n", raw):
            raise ValueError("Invalid invariant default HTTP timestamp marker")
        markers[name] = int(raw)
    if receipt.get("forced") is not False or receipt.get("diagnosticPrefill") != 0 or \
            receipt.get("bufferedOutput") != 0 or receipt.get("bufferedObservedTimestamp") != 0:
        raise ValueError("Default HTTP fixture termination or synthetic buffering is forbidden")
    frequency, exited = receipt.get("timestampFrequency"), receipt.get("exitObservedTimestamp")
    if type(frequency) is not int or frequency <= 0 or type(exited) is not int or \
            receipt.get("entryTimestamp") != markers["entered"] or \
            any(not markers["entered"] <= stamp <= exited for stamp in markers.values()):
        raise ValueError("Unbound default HTTP timestamp evidence")
    edges = [
        ("entered", "provider-created"), ("provider-created", "http-owner-created"),
        ("http-owner-created", "loader-entered"), ("loader-entered", "session-created"),
        ("session-created", "provider-ready"), ("ui-thread-started", "hidden-parent-created"),
        ("hidden-parent-created", "provider-ready"), ("provider-ready", "http-send-entered"),
        ("host-closing", "native-cleanup-completed"), ("native-cleanup-completed", "drain-boundary"),
        ("before-commit", "after-commit"), ("after-commit", "drain-boundary"),
    ]
    if cancellation:
        before, after = receipt.get("writerCloseBefore"), receipt.get("writerCloseAfter")
        if type(before) is not int or type(after) is not int or \
                not markers["host-callback-pending"] <= before <= after <= exited or \
                before > markers["http-cancel-observed"]:
            raise ValueError("Default HTTP cancellation lacks its actual writer-close interval")
        edges.extend((
            ("http-send-entered", "host-callback-pending"),
            ("host-closing", "host-callback-pending"),
            ("http-cancel-observed", "provider-callback-pending"),
            ("http-cancel-observed", "host-callback-forwarded"),
            ("provider-callback-pending", "pending-drain-observed"),
            ("host-callback-forwarded", "pending-drain-observed"),
            ("pending-drain-observed", "drain-release-observed"),
            ("drain-release-observed", "drain-boundary"),
        ))
    else:
        if receipt.get("writerCloseBefore") != 0 or receipt.get("writerCloseAfter") != 0:
            raise ValueError("Disposal-stall case must not close the input writer")
        edges.extend((("http-send-entered", "candidate-returned"), ("candidate-returned", "before-commit")))
    if expected == "green":
        edges.append(("drain-boundary", "http-dispose-entered"))
        edges.append(("http-dispose-entered", "http-dispose-completed" if cancellation else "dispose-stall-entered"))
    if cancellation or expected == "red":
        edges.append(("http-dispose-completed" if expected == "green" else "drain-boundary", "process-returned"))
    if any(markers[left] > markers[right] for left, right in edges):
        raise ValueError("Default HTTP causal marker order changed")
    # Preserve this observation bound; source review must still bind the earliest ending.
    if (exited - markers["host-closing"]) * 1000 > frequency * 1100:
        raise ValueError("Default HTTP exit exceeded the existing observed local ending bound")
    outcome = "cancelled" if cancellation else "success"
    exit_code = 1 if cancellation else 0 if expected == "red" else 2
    indication = b"Authentication request cancelled.\n" if cancellation else b"Authentication request completed.\n"
    if receipt.get("exitCode") != exit_code or not indication.startswith(paths["stderr.bin"].read_bytes()):
        raise ValueError("Default HTTP exit or optional fixed diagnostics changed")
    output = paths["stdout.bin"].read_bytes()
    if not output.endswith(b"\n") or output.count(b"\n") != 1 or output.startswith(b"\xef\xbb\xbf"):
        raise ValueError("Default HTTP output must be one UTF-8 protocol result")
    value = json.loads(output.decode("utf-8"), object_pairs_hook=pairs)
    if type(value.get("protocol")) is not int or value["protocol"] != 1 or value.get("outcome") != outcome:
        raise ValueError("Default HTTP protocol result changed")
    if cancellation:
        if set(value) != {"protocol", "outcome", "reason"} or value.get("reason") != "cancelled":
            raise ValueError("Default HTTP cancellation contains unexpected fields")
    elif value.get("accessToken") != "SYNTHETIC_PROCESS_SCENARIO_TOKEN" or \
            value.get("accountEmail") != "personal@example.test" or value.get("interaction") != "interactive":
        raise ValueError("Default HTTP success differs from the synthetic candidate")


@contextmanager
def preparation_budget(enabled):
    """Bound H preparation, including work before its action reservation."""
    if not enabled:
        yield lambda: None
        return

    def stop(number, _frame):
        if number == signal.SIGALRM:
            raise TimeoutError("WSL preparation expired")
        raise InterruptedError("WSL preparation interrupted")

    previous = {number: signal.signal(number, stop)
                for number in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)}
    signal.setitimer(signal.ITIMER_REAL, 1800)
    try:
        yield lambda: signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for number, handler in previous.items():
            signal.signal(number, handler)


def attendance_ready(action, reservation_hash):
    ready = read(action / "attendance-ready.json")
    if set(ready) != {"action", "reservationSha256", "waitSeconds", "invocationSha256",
                      "controllerSha256", "preparedUtc"} or ready["action"] != action.name or \
            ready["reservationSha256"] != reservation_hash or type(ready["waitSeconds"]) is not int or \
            ready["waitSeconds"] != ATTENDANCE_SECONDS or ready["invocationSha256"] != digest(action / "invocation.json") or \
            ready["controllerSha256"] != digest(action / "controller.json") or \
            not isinstance(ready["preparedUtc"], str):
        raise ValueError("Unbound attendance readiness")
    datetime.datetime.fromisoformat(ready["preparedUtc"])
    return digest(action / "attendance-ready.json")


def attendance_released(action, ready_hash):
    released = read(action / "attendance-released.json")
    name = "attendance-release-" + ready_hash
    if set(released) != {"readySha256", "releaseName", "waitMilliseconds"} or \
            released["readySha256"] != ready_hash or released["releaseName"] != name or \
            type(released["waitMilliseconds"]) is not int or not 0 <= released["waitMilliseconds"] < ATTENDANCE_SECONDS * 1000:
        raise ValueError("Unbound attendance release")
    marker = action / name
    direct(marker)
    if not marker.is_file() or marker.stat().st_size != 0 or \
            list(action.glob("attendance-release-*")) != [marker]:
        raise ValueError("Invalid attendance release marker")
    return released["waitMilliseconds"] / 1000


def windows_wait(command, seconds, cancel_path=None, attendance=None):
    """Keep one work allowance; exclude only the one actual attendance wait."""
    interrupted = False

    def cancel(_number, _frame):
        nonlocal interrupted
        interrupted = True

    old = {number: signal.signal(number, cancel) for number in (signal.SIGINT, signal.SIGTERM)}
    process = None
    try:
        began = time.monotonic()
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        cancellation_started = None
        ready_at = ready_hash = None
        excluded = 0
        release_seen = False
        while process.poll() is None:
            now = time.monotonic()
            if cancel_path is not None and cancel_path.exists():
                interrupted = True
            if attendance is not None and not interrupted:
                action, reservation_hash = attendance
                try:
                    if ready_at is None and (action / "attendance-ready.json").exists():
                        # Reject lateness before permitting any wait exclusion.
                        if now - began >= seconds:
                            raise TimeoutError("Windows preparation expired")
                        ready_hash = attendance_ready(action, reservation_hash)
                        ready_at = time.monotonic()
                        print(json.dumps({"action": action.name, "state": "awaiting-operator",
                                          "readySha256": ready_hash, "waitSeconds": ATTENDANCE_SECONDS}), flush=True)
                    if ready_at is not None and not release_seen:
                        excluded = min(time.monotonic() - ready_at, ATTENDANCE_SECONDS)
                        if (action / "attendance-released.json").exists():
                            # Receipt duration can only reduce the locally observed exclusion.
                            excluded = min(excluded, attendance_released(action, ready_hash))
                            release_seen = True
                        elif time.monotonic() - ready_at >= ATTENDANCE_SECONDS:
                            interrupted = True
                except (ValueError, OSError, KeyError, TypeError):
                    interrupted = True
            now = time.monotonic()
            if now - began - excluded >= seconds or now - began >= seconds + (ATTENDANCE_SECONDS if attendance else 0):
                if cancel_path is not None:
                    cancel_path.touch(exist_ok=True)
                return None, True
            if interrupted and cancellation_started is None:
                cancellation_started = now
                if cancel_path is not None:
                    cancel_path.touch(exist_ok=True)
            if cancellation_started is not None and now - cancellation_started >= 15:
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


def prepare_source(source, action, graph_transition=False):
    subject = ROOT / "subject"
    if not subject.exists():
        git("worktree", "add", "--detach", str(subject), source)
    else:
        git("diff", "--exit-code", "HEAD", cwd=subject)
        if graph_transition:
            paths = set(git("ls-tree", "-r", "--name-only", source).splitlines())
            if any(name in paths for name in (*SUPERSEDED_LOCKS, "src/Authentication.Cli/packages.lock.json")):
                raise ValueError("Graph-establishment source must declare regenerated locks")
            retained = {}
            for name in SUPERSEDED_LOCKS:
                saved = action / "superseded-locks" / name
                saved.parent.mkdir(parents=True, exist_ok=True)
                with saved.open("xb") as stream:
                    stream.write((subject / name).read_bytes())
                retained[name] = digest(saved)
            write_new(action / "lock-transition.json", {
                "priorSource": git("rev-parse", "HEAD", cwd=subject), "source": source,
                "priorRestoreReceiptSha256": digest(ROOT / "actions/0004/restore.json"),
                "retainedSha256": retained,
            })
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
    parser.add_argument("--suite", choices=("cli", "adapter", "owned-host", "local-provider", "host-admission", "ui-admission", "owned-process", "msal-composition", "msal-construction", "default-http-composition"))
    args = parser.parse_args()
    if (args.action == "test") != (args.suite is not None):
        raise ValueError("Test actions require one finite suite; other actions forbid it")
    attended = args.action == "test" and (args.suite in ("ui-admission", "owned-process", "default-http-composition") or
                                         args.suite == "owned-host" and args.expect == "green")
    with preparation_budget(attended) as finish_preparation:
        return execute(args, attended, finish_preparation)


def execute(args, attended, finish_preparation):
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
    direct(LINUX)
    stat = LINUX.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o777 != 0o700 or read(LINUX / "owner.json") != {
        "issue": 108, "grant": GRANT, "protocol_family": PROTOCOL,
    }:
        raise ValueError("Unrecognized Linux ownership/history")
    # Reuse the Linux action lock: neither loop can execute while the other owns it.
    with (LINUX / "action.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        admitted_tools = installed_packs()
        for path, expected in admitted_tools.items():
            if digest(Path("/mnt/c") / path[3:].replace("\\", "/")) != expected:
                raise ValueError("Installed tool identity changed")
        if not HISTORY.exists():
            HISTORY.mkdir(mode=0o700)
        linux, previous = histories()
        if previous and previous[-1][0].name in ("0002", "0003") and (
            args.action != "restore" or args.source != previous[-1][1]["source"]
        ):
            raise ValueError("The first continuation must restore the unchanged admitted source")
        if previous and previous[-1][0].name == "0006" and (
            args.action != "test" or args.expect != "red" or args.source != previous[-1][1]["source"]
        ):
            raise ValueError("The first continuation must test the unchanged admitted red build")
        if len(previous) < 14 or digest(HISTORY / "0014/result.json") != ADAPTER_PRIOR_FINAL or \
                digest(HISTORY / "0014/started.json") != ADAPTER_PRIOR_START:
            raise ValueError("Accepted CLI green history prerequisite changed")
        if len(previous) < 18 or digest(HISTORY / "0018/result.json") != OWNED_HOST_PRIOR_FINAL or \
                digest(HISTORY / "0018/started.json") != OWNED_HOST_PRIOR_START:
            raise ValueError("Accepted adapter green history prerequisite changed")
        if len(previous) < 21 or digest(HISTORY / "0021/started.json") != WAVE_REFRESH_PRIOR_START or \
                digest(HISTORY / "0021/result.json") != WAVE_REFRESH_PRIOR_FINAL:
            raise ValueError("Accepted owned-host green build prerequisite changed")
        if len(previous) < 22 or digest(HISTORY / "0022/result.json") != DISPOSED_WINDOWS_ATTENDANCE["result.json"]:
            raise ValueError("Accepted attendance-expiry disposition prerequisite changed")
        if len(previous) < 23 or digest(HISTORY / "0023/started.json") != LOCAL_PROVIDER_PRIOR_START or \
                digest(HISTORY / "0023/result.json") != LOCAL_PROVIDER_PRIOR_FINAL:
            raise ValueError("Accepted owned-host green result prerequisite changed")
        if len(previous) < 27 or digest(HISTORY / "0027/started.json") != HOST_ADMISSION_PRIOR_START or \
                digest(HISTORY / "0027/result.json") != HOST_ADMISSION_PRIOR_FINAL:
            raise ValueError("Accepted local-provider green result prerequisite changed")
        if len(previous) < 31 or digest(HISTORY / "0031/started.json") != UI_ADMISSION_PRIOR_START or \
                digest(HISTORY / "0031/result.json") != UI_ADMISSION_PRIOR_FINAL:
            raise ValueError("Accepted host-admission green result prerequisite changed")
        if len(previous) < 34:
            raise ValueError("The extended attendance disposition requires all thirty-four Windows actions")
        if len(previous) < 37 or digest(HISTORY / "0037/started.json") != OWNED_PROCESS_PRIOR_START or \
                digest(HISTORY / "0037/result.json") != OWNED_PROCESS_PRIOR_FINAL:
            raise ValueError("Accepted UI-admission green history prerequisite changed")
        if len(previous) < 39:
            raise ValueError("The owned-process disposition requires all thirty-nine Windows actions")
        if len(previous) < 41 or digest(HISTORY / "0041/started.json") != MSAL_COMPOSITION_PRIOR_START or \
                digest(HISTORY / "0041/result.json") != MSAL_COMPOSITION_PRIOR_FINAL:
            raise ValueError("Accepted owned-process green history prerequisite changed")
        if len(previous) < 45 or digest(HISTORY / "0045/started.json") != MSAL_CONSTRUCTION_PRIOR_START or \
                digest(HISTORY / "0045/result.json") != MSAL_CONSTRUCTION_PRIOR_FINAL:
            raise ValueError("Accepted MSAL composition green history prerequisite changed")
        if type(DEFAULT_HTTP_PRIOR_ACTION) is not int or DEFAULT_HTTP_PRIOR_ACTION <= 46 or \
                any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in (DEFAULT_HTTP_PRIOR_START, DEFAULT_HTTP_PRIOR_FINAL)) or \
                not isinstance(DEFAULT_HTTP_PRIOR_PROTOCOL, str) or \
                not re.fullmatch(r"[0-9a-f]{40}", DEFAULT_HTTP_PRIOR_PROTOCOL):
            raise ValueError("Default HTTP preceding accepted identities are unresolved")
        prior_name = f"{DEFAULT_HTTP_PRIOR_ACTION:04d}"
        if len(previous) < DEFAULT_HTTP_PRIOR_ACTION or \
                digest(HISTORY / prior_name / "started.json") != DEFAULT_HTTP_PRIOR_START or \
                digest(HISTORY / prior_name / "result.json") != DEFAULT_HTTP_PRIOR_FINAL or \
                previous[DEFAULT_HTTP_PRIOR_ACTION - 1][1]["protocol"] != DEFAULT_HTTP_PRIOR_PROTOCOL:
            raise ValueError("Accepted construction completion prerequisite changed")
        default_http_transition = len(previous) == DEFAULT_HTTP_PRIOR_ACTION
        if default_http_transition and (args.action != "build" or args.source == previous[-1][1]["source"]):
            raise ValueError("The first default HTTP action must build new admitted source with its retaining migration")
        default_http_cycle = (
            ("build", None, "green"), ("test", "default-http-composition", "red"),
            ("build", None, "green"), ("test", "default-http-composition", "green"),
        )
        advanced = previous[DEFAULT_HTTP_PRIOR_ACTION:]
        if len(advanced) >= len(default_http_cycle) or any(
                (start["action"], start["testSuite"], start["expected"]) != default_http_cycle[index]
                for index, (_, start, _) in enumerate(advanced)) or \
                (args.action, args.suite, args.expect) != default_http_cycle[len(advanced)]:
            raise ValueError("Default HTTP permits only one separately admitted red/green build/test cycle")
        msal_construction_transition = len(previous) == 45
        if msal_construction_transition and args.action != "build":
            raise ValueError("The first MSAL construction action must build with its controller transition")
        if args.suite == "msal-construction":
            prior_construction = [start for _, start, _ in previous
                                  if start.get("testSuite") == "msal-construction"]
            wanted = [] if args.expect == "red" else ["red"]
            if [start["expected"] for start in prior_construction] != wanted:
                raise ValueError("MSAL construction permits one red and one subsequent green test")
        msal_composition_transition = len(previous) == 41
        if msal_composition_transition and args.action != "build":
            raise ValueError("The first MSAL composition action must build with its controller transition")
        if args.suite == "msal-composition":
            prior_composition = [start for _, start, _ in previous
                                 if start.get("testSuite") == "msal-composition"]
            wanted = [] if args.expect == "red" else ["red"]
            if [start["expected"] for start in prior_composition] != wanted:
                raise ValueError("MSAL composition permits one red and one subsequent green test")
        diagnostics_transition = len(previous) == 39
        if diagnostics_transition and (args.action != "build" or args.source == previous[-1][1]["source"]):
            raise ValueError("Disposed owned-process red requires a newly admitted corrected-source build")
        if args.suite == "owned-process" and args.expect != "green":
            raise ValueError("The owned-process red reservation is consumed; only green remains")
        owned_process_transition = len(previous) == 37
        if owned_process_transition and args.action != "build":
            raise ValueError("The first owned-process action must build with its controller transition")
        extended_attendance_transition = len(previous) == 34
        if extended_attendance_transition and (
            args.action != "test" or args.suite != "ui-admission" or args.expect != "red" or
            args.source != previous[-1][1]["source"]
        ):
            raise ValueError("The first extended wait must test the unchanged admitted UI red build")
        ui_attendance_transition = len(previous) == 33
        if ui_attendance_transition and (
            args.action != "test" or args.suite != "ui-admission" or args.expect != "red" or
            args.source != previous[-1][1]["source"]
        ):
            raise ValueError("The first continuation must test the unchanged admitted UI red build")
        ui_admission_transition = len(previous) == 31
        if ui_admission_transition and args.action != "build":
            raise ValueError("The first UI-admission action must build with its controller transition")
        host_admission_transition = len(previous) == 27
        if host_admission_transition and args.action != "build":
            raise ValueError("The first host-admission action must build with its controller transition")
        local_provider_transition = len(previous) == 23
        if local_provider_transition and args.action != "build":
            raise ValueError("The first local-provider action must build with its controller transition")
        attendance_transition = len(previous) == 22
        if attendance_transition and (
            args.action != "test" or args.suite != "owned-host" or args.expect != "green" or
            args.source != previous[-1][1]["source"]
        ):
            raise ValueError("The first continuation must test the unchanged admitted owned-host build")
        wave_refresh_transition = len(previous) == 21
        if wave_refresh_transition and (
            args.action != "test" or args.suite != "owned-host" or args.expect != "green" or
            args.source != previous[-1][1]["source"]
        ):
            raise ValueError("The Wave refresh must test the unchanged admitted owned-host green build")
        owned_host_transition = len(previous) == 18
        if owned_host_transition and args.action != "build":
            raise ValueError("The first owned-host action must build with its controller transition")
        adapter_transition = len(previous) == 14
        if adapter_transition and args.action != "build":
            raise ValueError("The first adapter action must build with its controller transition")
        graph_transition = len(previous) == 9
        if graph_transition and args.action != "restore":
            raise ValueError("The first process increment action establishes its new graph")
        if len(previous) < 9:
            raise ValueError("This amendment requires the completed accepted file history")
        reserved_processes = (12 if args.suite == "cli" else 10 if args.suite == "owned-process" else
                              2 if args.suite == "default-http-composition" else 0)
        prior_processes = 0
        owned_processes = 0
        default_http_processes = 0
        for historical, started, _ in previous:
            reservation = windows_process_reservation(int(historical.name), started)
            prior_processes += reservation
            if started.get("testSuite") == "owned-process":
                owned_processes += reservation
            if started.get("testSuite") == "default-http-composition":
                default_http_processes += reservation
        new_owned = reserved_processes if args.suite == "owned-process" else 0
        new_default_http = reserved_processes if args.suite == "default-http-composition" else 0
        if prior_processes + reserved_processes > 60 or owned_processes + new_owned > 20 or \
                default_http_processes + new_default_http > 4 or \
                prior_processes - owned_processes - default_http_processes + \
                reserved_processes - new_owned - new_default_http > 36:
            raise ValueError("Process scenario allocation exhausted")
        preparation = args.action in ("bootstrap", "restore")
        prep = sum(start["action"] in ("bootstrap", "restore") for _, start, _ in previous)
        tests = len(previous) - prep
        if prep + preparation > 5 or tests + (not preparation) > 48:
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
                 "priorWindowsPreparation": prep, "priorWindowsBuildTest": tests,
                 "reservedProcessScenarios": reserved_processes, "priorProcessScenarios": prior_processes,
                 "graphTransition": graph_transition, "testSuite": args.suite}
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
            previous_controllers = (DEFAULT_HTTP_PREVIOUS_CONTROLLERS if default_http_transition else
                                    MSAL_CONSTRUCTION_PREVIOUS_CONTROLLERS if msal_construction_transition else
                                    MSAL_COMPOSITION_PREVIOUS_CONTROLLERS if msal_composition_transition else
                                    PREVIOUS_CONTROLLERS if len(previous) == 3 else
                                    TEST_PREVIOUS_CONTROLLERS if len(previous) == 6 else
                                    PROCESS_PREVIOUS_CONTROLLERS if graph_transition else
                                    ADAPTER_PREVIOUS_CONTROLLERS if adapter_transition else
                                    OWNED_HOST_PREVIOUS_CONTROLLERS if owned_host_transition else
                                    WAVE_REFRESH_PREVIOUS_CONTROLLERS if wave_refresh_transition else
                                    ATTENDANCE_PREVIOUS_CONTROLLERS if attendance_transition else
                                    LOCAL_PROVIDER_PREVIOUS_CONTROLLERS if local_provider_transition else
                                    HOST_ADMISSION_PREVIOUS_CONTROLLERS if host_admission_transition else
                                    UI_ADMISSION_PREVIOUS_CONTROLLERS if ui_admission_transition else
                                    UI_ATTENDANCE_PREVIOUS_CONTROLLERS if ui_attendance_transition else
                                    EXTENDED_ATTENDANCE_PREVIOUS_CONTROLLERS if extended_attendance_transition else
                                    OWNED_PROCESS_PREVIOUS_CONTROLLERS if owned_process_transition else
                                    {"run_windows.py": "10c7e85802ef7ed2c2c31acaeaa871141c5ae78da3bd7c557a28fac44eb2b030"}
                                    if diagnostics_transition else {})
            for name in CONTROLLERS:
                data = (REPOSITORY / "tools/validation" / name).read_bytes()
                path = ROOT / "controller" / name
                direct(path)
                if name in previous_controllers and not path.exists():
                    raise ValueError("The pre-migration Windows controller disappeared")
                if path.exists():
                    if name in previous_controllers:
                        expected_previous = previous_controllers[name]
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
                    if not (graph_transition and name in PROCESS_ARCHIVES):
                        raise ValueError("Public feed lost an input")
                    with path.open("xb") as stream:
                        stream.write(original.read_bytes())
                if digest(path, "sha512") != expected:
                    raise ValueError("Copied archive identity changed")
                admitted_files = verify_cache(original, retained_cache, content_hash)
                cache = ROOT / "packages" / retained_cache.parent.name / retained_cache.name
                if not cache.exists():
                    if not (graph_transition and name in PROCESS_ARCHIVES):
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
            before = prepare_source(args.source, action, graph_transition)
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
            start.update(fileSha256=inputs, toolSha256=admitted_tools)
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
            finish_preparation()
            launched = True
            code, interrupted = windows_wait(command, 230, action / "cancel",
                                             (action, digest(action / "started.json")) if attended else None)
            if code is None:
                raise ValueError("Windows controller wait expired")
            win = read(action / "windows-result.json")
            result["quiescent"] = win.get("quiescent") is True
            if interrupted or code != 0 or win.get("safetyStop") is not False or not result["quiescent"] or \
                    win.get("reservationSha256") != digest(action / "started.json"):
                raise ValueError("Windows action stopped")
            if attended:
                ready_hash = attendance_ready(action, digest(action / "started.json"))
                attendance_released(action, ready_hash)
                if win.get("attendanceReadySha256") != ready_hash or \
                        win.get("attendanceReleasedSha256") != digest(action / "attendance-released.json") or \
                        (action / "cancel").exists():
                    raise ValueError("Final attendance binding changed")
            if any((action / "temp" / marker).exists()
                   for marker in ("owned-host-safety-stop.json", "process-safety-stop.json")):
                raise ValueError("Owned fixture safety stop forbids continuation")
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
            for name, expected in admitted_tools.items():
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
                report = ET.parse(reports[0])
                invocation = read(action / "invocation.json")
                expected_arguments = (
                    "tests\\Authentication.Windows.Scenarios\\bin\\Release\\net10.0-windows\\Authentication.Windows.Scenarios.dll"
                    + ' --report-trx --results-directory "' + WINDOWS + "\\actions\\" + action.name
                    + '\\results" --filter "' + TEST_FILTERS[args.suite] + '"')
                if invocation["arguments"] != expected_arguments:
                    raise ValueError("Windows test selection differs from the admitted literal")
                result["tests"] = validate_selected_report(report, args.suite, args.expect)
                if args.suite in ("cli", "owned-process", "default-http-composition"):
                    process_evidence(action, args.expect, args.suite)
                elif any(path.name.startswith("process-") for path in action.rglob("*")):
                    raise ValueError("Child-free selection produced forbidden process evidence")
            result["continuation_allowed"] = True
        except Exception as error:
            result["error_type"] = type(error).__name__
            if launched and not result["quiescent"]:
                windows_wait(powershell("-File", WINDOWS + "\\controller\\Stop-WindowsValidation.ps1",
                                        "-ActionName", action.name), 10)
                # Emergency controller absence is never accepted as Job quiescence.
        finally:
            finish_preparation()
            result["utc"] = utc()
            if result["quiescent"]:
                result["evidence"] = {str(path.relative_to(action)): digest(path)
                                      for path in action.rglob("*") if path.is_file() and
                                      "home" not in path.relative_to(action).parts and
                                      ("temp" not in path.relative_to(action).parts or
                                       (path.relative_to(action).parts[1].startswith("process-") or
                                        path.relative_to(action).parts[1] == "owned-host-safety-stop.json"))}
            write_new(local / "result.json", result)
        print(json.dumps({"action": local.name, "continuation_allowed": result["continuation_allowed"],
                          "quiescent": result["quiescent"], "tests": result.get("tests")}))
        return 0 if result["continuation_allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
