"""Inert direct WSL transport proposal. Never imports its result helper by default."""

ExecutionAdmitted = False
if not ExecutionAdmitted:
    raise SystemExit(125)

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import hashlib
import sys
import types
import os
import re
import selectors
import stat
import subprocess
import time


SLOTS = frozenset(("R2", "R3", "R4", "R9", "R10", "D0", "D1", "D2"))
FIXTURE_SLOTS = frozenset(("D1", "D2"))
CLOSE_SLOTS = frozenset(("R9", "D2"))
FINAL_EXTRA = frozenset(("passed", "workerExited", "observerJobZero", "observerJobTotal",
    "observerStopAttempted", "observerStopSucceeded", "fault", "nativeEvidence",
    "productInObserverJob", "productLifetimeKnown", "traceStopped", "traceDrained",
    "traceZeroLoss", "targetStopAttempted", "retainedHandleExited", "callbacks",
    "eventsLost", "logBuffersLost", "realTimeBuffersLost", "nativeExit", "nativeDurationMs",
    "anchorAckPublished", "endByAnchorDeadline", "anchorToEndUpperBoundMs", "scenarioAccepted"))


class SafeFailure(Exception):
    pass


def require(value):
    if not value:
        raise SafeFailure()


@dataclass(frozen=True, repr=False)
class PublicPlan:
    slot: str
    nonce: str
    product_image: str
    product_linux_image: str
    observer_image: str
    observer_linux_image: str
    working_directory: str
    record_directory: str
    product_sha256: str
    caller_sha256: str
    protocol_sha256: str
    expected_exit: int
    product_timeout_seconds: int
    admission_path: str
    admission_sha256: str


@dataclass(frozen=True, repr=False)
class PrivateRequest:
    profile_path: str
    tenant_argument: str
    expected: object
    lifetime_pipe: bool
    close_after_ms: int | None
    default_association_independently_accepted: bool
    fixture_case: str | None = None


def fixture_request(slot, validator):
    require(slot in FIXTURE_SLOTS)
    close = slot == "D2"
    return PrivateRequest(
        profile_path=r"C:\synthetic\profile.json",
        tenant_argument="12345678-1234-4abc-8abc-1234567890ab",
        expected=validator.Expected(
            email="fixture@example.invalid",
            tenant="12345678-1234-4abc-8abc-1234567890ab",
            scopes=("12345678-1234-4abc-8abc-1234567890ab/read",),
            interaction_allowed=False,
            outcome="cancelled" if close else "success",
            required_interaction=None if close else "silent"),
        lifetime_pipe=close, close_after_ms=100 if close else None,
        default_association_independently_accepted=False, fixture_case=slot)




DIRECT_BASE_INPUTS = {'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\Microsoft.CSharp.dll': (980776, '2000912f2fc52e0c64ed893d79f4e7b143502540fb7170b5ae5fcea7099ba431', 980776), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\Microsoft.NETCore.App.deps.json': (29720, 'db6bf68420f350411629571d31aea9232f05e9464e0f48f306041efd0971615d', 29720), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\Microsoft.NETCore.App.runtimeconfig.json': (54, '31c8ce517cddc0deaceb26b5dff6ba5df55ac4e06e9afd0026e51faca23dc8a4', 54), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\Microsoft.VisualBasic.Core.dll': (1193768, '2666b24eb6e295476b44abd057ea250fd5957db9c1c7adee6a223a747ddfe3d2', 1193768), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\Microsoft.VisualBasic.dll': (17192, 'e192508adde6a758138a5a8e28998dccb64e7f45eaf30d8ab3564f87749028b1', 17192), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\Microsoft.Win32.Primitives.dll': (15656, '6c21472b0ae2f9b484a97614fad5485a22f18f9f19ee1adb9ceb3ed8ddb072d7', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\Microsoft.Win32.Registry.dll': (116520, '76849cfde4369f3ae93e28261fe5e1010dbf1332f7da95c98543cba9b03961c0', 116520), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.AppContext.dll': (15144, 'd9dd9fa44e019f27172d6b2662e2b6038f48c270912ac8aae53d4d909da7e9be', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Buffers.dll': (15144, 'a1a35f5524e2f831d08ca55f702fbddcb8c6dfecd264f0f563d81a1c8b8280bd', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Collections.Concurrent.dll': (231248, '082f4bc0da1141eb65111b6da633d75624adfb7bb067d7ee90c5622c8b30885b', 231248), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Collections.Immutable.dll': (976680, 'b527dd7b2beb82c22aa39787298cbeb33f3eac9eb9b83a0f0271353421db28db', 976680), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Collections.NonGeneric.dll': (104232, 'aa4d5216d066c91cb489f63c6cbfcaf1f47b6e74e070db45639d3460454fc60b', 104232), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Collections.Specialized.dll': (104272, 'e31af1f866e880844e027be59f545b9a6b34108e0b0680ebe3fbc19a53070819', 104272), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Collections.dll': (296744, 'df6f2037eabee28100184e92f7536427ba2f086c1110629804d466b124bc4d54', 296744), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ComponentModel.Annotations.dll': (198480, 'e3be2d35d81e6475c64110cfc099895b71df22c8b46a18c2d7c76a913b8ba903', 198480), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ComponentModel.DataAnnotations.dll': (16720, 'd40e8c7062e6b9ce11ba83eab3d26be0eec8066b99970ea88b8e87fb75f411bd', 16720), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ComponentModel.EventBasedAsync.dll': (46888, 'cc84fe814ef5e58271d83193e328f8ec220efd4696d90af9a7c4690c10451495', 46888), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ComponentModel.Primitives.dll': (79656, '1e2451184c287409ea25acde3c90f25950bf34d16458a6e52a94ca4292434f62', 79656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ComponentModel.TypeConverter.dll': (767784, '10dae312a6697718f8ce3dfcdb17d6ae4b74687c765d74d50de8a8e69e08f5e7', 767784), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ComponentModel.dll': (30544, 'e3b6f75864ee944898540937c1f300e04f44a1b2729516f0bbf948589a8b14b2', 30544), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Configuration.dll': (19240, '3952a72e1f18774f16952b46c20e80ed2bc601a06eca01f33fa924c738022a9c', 19240), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Console.dll': (169808, '3b85daf02a3d9ed99b84bb1c639fe8b1ced46d8d157fa56f525f6b8c5be43b3e', 169808), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Core.dll': (23336, 'ac23faf1b37fa49f1b117baad951a65609e799a6e669a6df06d3552677e0c086', 23336), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Data.Common.dll': (2770728, '66bdd62047ee460e2ce2c33d15dd1173ac97997b2745864a905179594f821acc', 2770728), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Data.DataSetExtensions.dll': (15656, 'aeeae0755c8c7f6747765cdf82fa43182e320e97f2035e3a0a19f21905e6c113', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Data.dll': (25424, '49f52958a2a6e461d0fd7a47e54a199eb263c69ecfcc0fc684b73b5918ebf466', 25424), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.Contracts.dll': (16208, '6c05cacd9b61b08ae75f2d783cc402b0b5fc848e3d68c29c10b93897cc083e8b', 16208), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.Debug.dll': (15656, '8b160ffe7518588bf64e13c01c6dcb2ef504d64f38bbf0f198d31e7b698db92c', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.DiagnosticSource.dll': (501544, '6267c1bd1bdf2bdd4b5748b885b0adcda10f18697adfea8488a19a009ad44fdb', 501544), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.FileVersionInfo.dll': (46928, 'e94f158142e93834dec3100bde3313935517d549ff36c65819a06d3104dec427', 46928), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.Process.dll': (329552, '51a57fbe918f8b68930c090792b718fc0850ea12da869d50b97a3796af29a740', 329552), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.StackTrace.dll': (46888, '8f6397c1e2ba9b8b8bfa317962151b5035049ce8d6b3575e5027a0d0eeacc797', 46888), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.TextWriterTraceListener.dll': (67368, '1bf165cee916a854e1150f489e4348ce94755359d5fcdcc0bc2bbbe6a7102bdd', 67368), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.Tools.dll': (15144, '841c5e2b6c171fa9aaff0fc6295f3fbc93dc5dcab44118b62f1c942bb674aff2', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.TraceSource.dll': (141096, '8445c7f1bbaae6cffde60e2c9a8753faaa5100255fbe31d0a1927d9d9bb7f194', 141096), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Diagnostics.Tracing.dll': (16208, '9563d5eec35f94d13a5e62eaa9535dbe0e9ea474f055da132fb8af46b0b01263', 16208), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Drawing.Primitives.dll': (132944, '17585b32ca91bac8ccff2ef1c6ddf62ee9ea5efc552928c3a9d1b868394246e9', 132944), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Drawing.dll': (20304, '585a8da9952d715f8de7a7b1879b59d68ff8608b92f6ed1c5f0e1d251180d3c6', 20304), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Dynamic.Runtime.dll': (16168, 'c0eac30c791db8c1a2b50b61c50d029f4ddd0eadfdd35433745001688a3e7466', 16168), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Formats.Asn1.dll': (239440, 'a163fe5f96d1689f1bc1ac531b38c3aba95792ac7dd52231d325d658947fbcfd', 239440), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Formats.Tar.dll': (272168, '44c9984f269a158915195fd32007f22c3bb692dcfeb933cda8ea45a3ac6cd1ce', 272168), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Globalization.Calendars.dll': (15656, 'e0f3f3f6e4acc7b6755782fed5cb075ecf70beee4fc5d404579ae99bc0883ef2', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Globalization.Extensions.dll': (15144, 'be0390557cc72078a7217cf94fd44b9ab66aa30838c00a92aa78c62469c44aa0', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Globalization.dll': (15696, '66902cffd057673b4b77aa68faf80d33ffa4c94510e61db2a067943cc53b7702', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.Compression.Brotli.dll': (83752, '0a59a95787ee15784d73079fdd5dc555b78659a6c560b6cbbf0d7452e638df89', 83752), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.Compression.FileSystem.dll': (15184, '4aeec2c0189f73ba8122f05c0d759008ddae1a8873b167cc8a558d53f2af80e1', 15184), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.Compression.ZipFile.dll': (100176, '2da76eb281740be485b5637da8c60fe0ce12bc2848d1a1a81ce144fa74313e18', 100176), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.Compression.dll': (419624, 'c942747f84b730887090f5e0cf86d164c0ee402e524dce2750e06a6df48513fb', 419624), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.FileSystem.AccessControl.dll': (104232, 'f7f9ed6cdab35274711e9345266784ec332ae8040db184d141c70e7941fbbec5', 104232), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.FileSystem.DriveInfo.dll': (55120, '0a7f3dd2fb6147a3fc046aeac8501d764effe5a3d8cfa56d2b244aa50b874b98', 55120), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.FileSystem.Primitives.dll': (15144, 'd3b21b8b38e48c6b4d1cb5cfe9adfe4abad7b3353601febd3c7e4027f9ef9c6b', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.FileSystem.Watcher.dll': (87848, '8ab1704e4bd171056ec5a11e886d5199d05a641c6d0233c53d4766bf30328dd3', 87848), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.FileSystem.dll': (15656, 'c251f33b29382c47b773d907463edd9fe978a06e39efd5670ef3b3b1d4f8c2b7', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.IsolatedStorage.dll': (87848, '2272a8bde18ed0e7c9e54ece9b849b9be76c90b978909d2b2fc94cf0ccbce427', 87848), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.MemoryMappedFiles.dll': (83752, '6e8b281ecb2f0f5e7aad3980f61d8812caa6b37884737f542f95410a76663e0e', 83752), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.Pipelines.dll': (190248, 'ee9f0fd6c659f50799afd103c6ed9c5e408967e28dfa059bddf4b0a3fd2557dd', 190248), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.Pipes.AccessControl.dll': (15656, '1102f25a6e88f2fae81e4cd3628d8ef826f847b9c9b6a4d32ff8b37e0300da35', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.Pipes.dll': (165712, '3804f9992861122e60990b0765d0b50b33cdc2e4d89d26d9dbf8641d1d0134a2', 165712), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.UnmanagedMemoryStream.dll': (15696, 'ad6a5f859589e1951103a00f45566da079cf87bd8b03f0c6ad985a6f39f19c5a', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.dll': (15656, '388400ccb189b819d6ec5f1ef70710a39641d93ed5b870fc9324866b75dfb78b', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Linq.AsyncEnumerable.dll': (1292072, '925208e8ac40ac3f7b988aba6ccbbb58adac38ad1876a7d97ee137be6c21a653', 1292072), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Linq.Expressions.dll': (3639080, '8830f4a6a6982f53cfbb54f992858ee36b4994a6ff6e6078c39627e77bef282f', 3639080), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Linq.Parallel.dll': (775976, 'aa6068e3d8f6b2e492cc63dcaad6b02942edbae445cb2b88c24f1850b25c49f5', 775976), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Linq.Queryable.dll': (182056, 'b3b3a9c1b87a51dacd46a3f9ec392c5d05e449152d44d6bd495df0994350e2fa', 182056), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Linq.dll': (698192, '284d38945b6e92e847129bd28af458b19818d0f2181f79882888ab2003f4c519', 698192), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Memory.dll': (161576, 'f8f9d38efd6b0de30954d6bf1f353e9617bfb36d3d245c013a3b12be9f6bd88a', 161576), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Http.Json.dll': (128848, 'a9fe81ba3c048f9977e0099800eefd570a49be723c555725da57ba797c92b4e0', 128848), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Http.dll': (1746768, 'b98ed0cb80dd54c33fc049f33af5448710752155bbd5cc8cbcd932e01f066801', 1746768), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.HttpListener.dll': (534312, '3dfe11fb30c5f84c911d9562be6c2037113cd8976ef2def3550ac415ae58955b', 534312), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Mail.dll': (481064, 'b585a55ee67c80d7f02a84d50d626d279c7aa77fd3e38206b434bd20c181eedc', 481064), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.NameResolution.dll': (124712, 'e786c0940f5322f0ad6e8e34e7b582e5b050df0fb2230329325307e61bfd994c', 124712), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.NetworkInformation.dll': (157520, '7e8791833eb2d0aea77b119fed3cab8bf501f6a553155cc1c4e5b1c02f65593b', 157520), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Ping.dll': (91984, '06bb307343db955a312634d00ba5e097cf5168a901284437592c28d780804e33', 91984), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Primitives.dll': (210728, '4dbb41a178ef013a898327152eccd146228dd2eb83859b9bb36078333b41f0f1', 210728), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Quic.dll': (358224, 'af5b52cdee62d014af677c411530a3fde5c1c368adecb8f83dcfe9246e8bbe73', 358224), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Requests.dll': (374568, 'ed82d9d0b7942b2b02c5744a4591fbe2316879618adfc5660c9f111f814155f2', 374568), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Security.dll': (665424, 'a78bd713e807729f15b0e085c67fd6cbfefa85736a2618512d4ff1212759eba5', 665424), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.ServerSentEvents.dll': (83752, 'c0b1944020d0e5688b90fba9f29209e367674e29d2020f700c302994d5417eda', 83752), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.ServicePoint.dll': (15144, '84fa83cd96e62fda02991b8a8e99fa1c7b3ac08807b04f7486a896cfe6b4a760', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.Sockets.dll': (530216, '645c56d637ce15976998119e50722a911315682ce141b4aab98874ce1b063f3a', 530216), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.WebClient.dll': (165672, 'defa7bbf90c77ed01d6add53f678e4adfbcf97f3b1152affec06e652d327f1a2', 165672), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.WebHeaderCollection.dll': (63312, '74d66f776b4c15936a7b887f47ceb8bf277dbe82e71a78dd3ea5d02502b081e7', 63312), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.WebProxy.dll': (42832, '408e3daabb3f42b4f1b72a1e1def38f12ba58eb9d23dca620086819cf7484195', 42832), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.WebSockets.Client.dll': (104232, 'f308a69b9ee1ac982f53d1d94374f4972a7e3c700742901ff7c2bbfb570019d2', 104232), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.WebSockets.dll': (243496, 'c014a074d408c71011e26eac69be85003a852cfe115e8608bb5d4fd70536eb2e', 243496), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Net.dll': (17192, '481b38c912f8779b3510cd00f079e45096ea22b6defdaab66780d5ac3ae6986a', 17192), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Numerics.Vectors.dll': (15656, 'a9a980ee33ed0c798a5e1960c4557521f465ac9e0987dfd2c3049d53b1f2fa5a', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Numerics.dll': (15184, '35adc9360421b3b7a3d50399cb2c651c160158d7e8c302907acbce5f61f4a4f7', 15184), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ObjectModel.dll': (79656, '2179bb19f335b4fcacd0994ad2ccfdac6840deff09c7889debfe9dbb5b88a3e6', 79656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Private.CoreLib.dll': (16033576, '1125acc8106c43fc8bad2d203c4c4485df6182d292846c2fff415c1040c54678', 16033576), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Private.DataContractSerialization.dll': (2062120, '8c07a5333c4e938cad8ac8f24b5965121bc0622442a352cbe81c58f17c2349a8', 2062120), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Private.Uri.dll': (255824, 'b15c84d2120e1ec9612c66ba59bc3d7e67d841e2bce7b7d0478cb212537539b4', 255824), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Private.Xml.Linq.dll': (390952, 'c832b73de9783e6929ca5ff4863fc313e13ef7cfb5965c52587c4f77f6e037a7', 390952), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Private.Xml.dll': (7788328, 'd71e72a7a9de324352edd281a46466b51bd0bdd2831b1573f8d3bae8bd2dd4a6', 7788328), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.DispatchProxy.dll': (75600, 'bf93a361c0bba8497889c9f7713add5968ba39394f9e6bda27e86294c6c43560', 75600), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.Emit.ILGeneration.dll': (15656, '6b42ddd05b0ca1c7342d73ea9f401fe588044215d65c67b756deb780f0894a26', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.Emit.Lightweight.dll': (15656, 'd2724a2b7b46146877ec1f6e400c49ea05f84bdd31f3bba52ae139ee68a4f779', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.Emit.dll': (309032, '09059981bbeea0fdc5df589be5d7e3937d57e22bec4d78ceb492c587926fc238', 309032), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.Extensions.dll': (15144, 'ceb1b81e1eb488d87bd43d16dc54450b2a78e0b653c44c988aae2a20abc162bc', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.Metadata.dll': (1156904, '82973e772017944a0548e445f30757595d95fe99e1f5c4a446df8c4db04b1c18', 1156904), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.Primitives.dll': (15656, 'c2bbd885d03da5e880667c228ac1f56a5f3a72ea37d43f010ada000adc33da28', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.TypeExtensions.dll': (42792, '7cac73ed746ce05a4a2f1e61dd52d41322ecc6ba84cfec463380f49487031459', 42792), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Reflection.dll': (16168, '95059346d6271dd6d0322cc321e5fb8cceab662f550c67aee7615059e41739bb', 16168), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Resources.Reader.dll': (15144, '20bdb5d302b5e28f6042c9f281cfa3ae2f2358544cc40783052fe5abf6aa859b', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Resources.ResourceManager.dll': (15696, 'f709eb5cf16e26679782784c428825019785fcc7085562092425d4999bece03d', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Resources.Writer.dll': (50984, '684836486b9ba2817efa3099118860d259fd16db0c4c0533d42cad8c6c165b62', 50984), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.CompilerServices.Unsafe.dll': (15184, '6e685ec0477b21a688cd38bfcafc673888cdf186c99df3c96fab352e96d6fdc8', 15184), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.CompilerServices.VisualC.dll': (30504, '5fd85d3d7b47a921bdf48bf938c6615a49a4a3d493e1ea199f1b997c709618f4', 30504), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Extensions.dll': (17704, '3d7b517d4fd89ee58c53e0f642cc9be42e7a8669b51a85e861dafe118067cbfd', 17704), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Handles.dll': (15656, '985457a3e6a67e96a445ee0fb69b2d58bcdadc4c964253fb63e2d5061a36b050', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.InteropServices.JavaScript.dll': (50984, '5ba32bcde2d72362db2d6e02763ece79fa35bc878b50493e956ce594307e997f', 50984), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.InteropServices.RuntimeInformation.dll': (15656, 'c26d9f94329422bd000f28f6c65fdc162bf9397a6d29e418a189d4ca49c5c3ec', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.InteropServices.dll': (112464, 'e5eb1679f3579c9141e2bb9dbdce62624a623f38d299805cc1de07bacd21841f', 112464), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Intrinsics.dll': (17192, 'b07694ec91f3a200acf0f8b37c6ce5fcf05126a9198ae156d839fa5ca8439dc5', 17192), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Loader.dll': (15656, '9b9b2a4f0358d9146e76178ddb87d019be380c78baa7dac853493d45df089f03', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Numerics.dll': (354128, '8ac94fb810c092a9297a903762e79a75ae07d7229d0721540c391f86d3d5d220', 354128), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Serialization.Formatters.dll': (124712, '5e8e957c6b7a63132555ede5bcf5fe6a59934c83300e28074ec6e9845ecdd17f', 124712), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Serialization.Json.dll': (15656, '2fd71e3545dab4fc89b3fe54d13a1142f26a0cf187ebe375b3f7fa210fcb2596', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Serialization.Primitives.dll': (38696, 'f96093940e64d8eead98c86de9773d3c9d12c2b033bc6b1312ac88398303fdf3', 38696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Serialization.Xml.dll': (16680, 'eedb66ea2cd1a26cc45a46d6631209ccbec959af82208872a93b3ae52f189222', 16680), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.Serialization.dll': (17192, 'd565fc261ca98cbd14833821f777860291e8a0f775de7aee91778a9f6647f6f4', 17192), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Runtime.dll': (44840, '76be53624f64b23d0249dfa0bbe85390086de7c44bfd490642ea86c6faaf44af', 44840), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.AccessControl.dll': (227112, 'cdc304f9ddb32023adb8db8953e56711c9b64462e4341d0b62e87ccd19dc7b10', 227112), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Claims.dll': (100176, 'c53c8a7e95d8296f951872fdd2e6334d11c20bffd4322f1a088773bf9dcaa3c2', 100176), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Cryptography.Algorithms.dll': (17232, 'eb99ae7dbe058a1b015aba6769ce1f65155b7ff51ff9a7203fcf6d7cdea5fef7', 17232), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Cryptography.Cng.dll': (16168, '7319f97896d92a7d0729cf28dc6c4d1f797c1520b656ee01a780eec726ec2c16', 16168), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Cryptography.Csp.dll': (16208, '4002af141e9cb29875b677841adf64a9681e5672c2595492dcbc161460d4e121', 16208), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Cryptography.Encoding.dll': (15656, '994494aec7760f40fade2264aa7c13eebae36360f0b1399a7134bb19c9d58fda', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Cryptography.OpenSsl.dll': (15656, '1a8902bbad1b577a98bec62a8472105dc1e9a253e390f69fbe3d167e93206968', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Cryptography.Primitives.dll': (15656, '194cccea9354bb248e44c954b5373f9069163f8f21524b3ee4b3185fe436bc15', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Cryptography.X509Certificates.dll': (16680, '7439c3b90bc2ee49a9275b28ed29052b4d48b45999ac1b7d25593033b1bb8dd6', 16680), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Cryptography.dll': (2549544, 'e0a839a540e47343b53a936b32d91599a3470005228d50fd0b896f8bbdcc65b0', 2549544), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Principal.Windows.dll': (178000, '2311a3f92971de918943573dfb66e04e25c1d543663951eb24e8eb1a0dcd4251', 178000), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.Principal.dll': (15144, '1d3e351058be3a33214b23b308fe57f78cd6fd4d8fad448fc84cbbe7376129f9', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.SecureString.dll': (15696, '73aac97072b7deefa4de9647bf822162224f1452ad467841b989ff89d4d94595', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Security.dll': (18256, 'd8efd304765e859369698efef9b3ca707defa8e142721fe5605d7a2de7d38375', 18256), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ServiceModel.Web.dll': (16680, 'ce91013ee3a9a9d69a85e258f7749e6ece488295d7cb66f7c1079f2e8678fc5e', 16680), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ServiceProcess.dll': (15696, '63fc498c9d04e3c4345dfdb8016ad0639d54562dd7d8c707c072792c854df944', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Text.Encoding.CodePages.dll': (862032, '226e216e33c94ef7594bdffe670ba4dc5907151c113cb41ac9e9d570227e1765', 862032), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Text.Encoding.Extensions.dll': (15656, '8f51b9535db64fe027a40d6076200b1a6b0889bf05f62bb8e68c3eb083c7f113', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Text.Encoding.dll': (15696, '5e347db6b4f9b2746d50e1ac85be2d9cc7dc4038fde98ac4295bc7030c83cda9', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Text.Encodings.Web.dll': (124752, 'd20431f20d992e71a4e82e5f25c822474e2f4097d8527972d3d78ea1f26e47c3', 124752), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Text.Json.dll': (1890128, 'fa99f413be21ed5f484a09093fe5f0beba7de3062cf9cc9f847dbf8108dba55a', 1890128), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Text.RegularExpressions.dll': (1034064, '060bcc88a688e687ff1404b83b5fb5cf17e19ec57f33d5b8a48ab494da83c134', 1034064), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.AccessControl.dll': (75560, '66d618b5522b3e4f7a3c7f2bd872fc378fa6f9bbdca3636854eb1a8cb948e631', 75560), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.Channels.dll': (157480, 'afc5deb3c32b3f64bced2025d0b01b316d41b691ebc6ccb1a2ec445ad4c15e39', 157480), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.Overlapped.dll': (15696, '89fde15f8e520c4bcbc6cbfdceba2baed8670cdf52399a4cd7a21c6efb276c1a', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.Tasks.Dataflow.dll': (472872, 'a895b0c73d3a1afc4d89c1d9e445ed447af12864c25aad2c4cb7398ff50aa934', 472872), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.Tasks.Extensions.dll': (15696, 'f148e3a1414b7c2763ae21529ad79ad759f7cfd3c885256b64b0d2209dec2613', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.Tasks.Parallel.dll': (132904, '6fa359bdbebb56be96339f244ed41658afcead5e010074da470df1115d1e7699', 132904), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.Tasks.dll': (16680, 'f80b21f7dae04377b73945456cabe25e2ab1f4b564095aed546c2aa571644567', 16680), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.Thread.dll': (15696, 'ce71949bb1ea67b686e799128582015ebf8758f1107e59e43f342ece3f662930', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.ThreadPool.dll': (15656, '58fbc6c4b9c72087152fd0f0670a527098c00b0c19ba8d0979d3ca5ce07c6936', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.Timer.dll': (15144, '9e4620846572f49aeb476aa99405071b4bbd0df4323e4e232787ed73642b1ee5', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Threading.dll': (83792, '6c32ed1bf8067e4169e8feddd15e6489b89d19d1c7aae1520a551b57745d0a60', 83792), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Transactions.Local.dll': (640808, '8d0283a311a16333ffb6f966d9765e4d8b866777ad99291a93b30db349a15bc4', 640808), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Transactions.dll': (16720, '56abfca0350c111d077b3d86a2469ea3da4fccc1871f7c51a8b4fdb664bb0ede', 16720), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.ValueTuple.dll': (15696, '07a5347f6a597e5e0d72109efa1a525697e8c3f74fb0029005500f8ebbf9187a', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Web.HttpUtility.dll': (63272, '2cedef51b0a2c2b84240583339ecf2422c650e3388aa46f3494160b93b673887', 63272), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Web.dll': (15144, 'bc260b3db247ad9a6e4a82a275da85c3691a41272cc745cb7eaefcf1f31cc817', 15144), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Windows.dll': (15696, '716eee98ceee87d38f0b301224462f8442aa793f4b1b9c3ffac315753320ab37', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.Linq.dll': (15696, 'ae04903b25717fa4695e7e63489091f0d461e791e0bd264c6c85250d668f540d', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.ReaderWriter.dll': (21840, '8e48fed4d12bcffff01e8059caafb564697275797d2f5ec6823fdd82b87fe938', 21840), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.Serialization.dll': (16208, '489694401c60905cb6dca8ef0bf738cb609cd45b337126a01c825b913086ba43', 16208), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.XDocument.dll': (15696, '3ff858607de5146051498a7124ef983bea280d86e165f993516c6c26af81cfb5', 15696), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.XPath.XDocument.dll': (30504, '5bcd27a7e93515b745993f6dda51391033883cb8a1a8a2e3dad5caed3548f0da', 30504), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.XPath.dll': (15656, 'c817b11c58d95fa942fbc62a4cfa8219e16dafa5641eb004cb2be424028ed5d8', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.XmlDocument.dll': (15656, 'a50b9b3a03596e36e73e7a7d54f4d018e8dcfaa7fe79e8cf900af8838ef3ec36', 15656), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.XmlSerializer.dll': (17744, '0b7d057c2b5b2272e8d4096a755edfd96f3cf03ab9aaa3fef54b462bf48d517e', 17744), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.Xml.dll': (23376, '277a84ba155fe7808a514f32694a8157ec9f0eeeef00ef9643e5250004054ff0', 23376), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.dll': (50472, 'ef135f0bda0c41e142fdbd67b93e5aa7911916cb250f7df302f4151a3bbfa380', 50472), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\WindowsBase.dll': (16208, '0ec46a38f29a234b9a4d0ae9364c8322f661a47c831c5b948f2787b7ca12dbbd', 16208), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\mscorlib.dll': (59728, 'b698595367a7d4fa57ccacab73751fde0bb8f2415345c62cdfe7ced890da2c0c', 59728), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\netstandard.dll': (100648, '3dc81dbc9dacd28261632c94410859eda24c2db50cd6c14309cbb2a434b50c57', 100648), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\Microsoft.DiaSymReader.Native.amd64.dll': (2377016, '70e4b89978ce57ef87b28f4921f3140c383b04aa96e7f3bdb3c4ebb898fd8a72', 2377016), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\System.IO.Compression.Native.dll': (937256, '4d174b78aa8b3516c7e3cec0355dfe9ae570894055c377d2e5565d077a9a7a1e', 937256), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\clretwrc.dll': (317736, '7a2186201c87bbc597a1b8b26facd88e68f03be4c4a4211fd65cc6595c72e45b', 317736), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\clrgc.dll': (674088, '65e2f97d263824bfb9f75f92e66ebd22229aaf3a5faddef9345811d856c8840e', 674088), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\clrgcexp.dll': (711464, '23a8050ec68542989b6da6cc906a90faf8a14e6416fd2871a260b781b1c374ae', 711464), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\clrjit.dll': (2092328, '0749d8fc8e944d0576e1bb47120f87add8f875e5cd8968995633063fc79256f6', 2092328), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\coreclr.dll': (4614992, '128aee8c62a673d64739e585e3876b61133571cec83a46240a62581d5465639b', 4614992), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\createdump.exe': (71552, '315307159925d33eb604186a512901d080ecfc4cd8b8198030a7d398c6af2b0b', 71552), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\hostfxr.dll': (379688, '838591885c5396fb0588a3aedc2f3e841d3afc67570868b1bce615264005a44c', 379688), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\hostpolicy.dll': (378664, 'e92a2e71eeeaf7c574e905935b3e3724ef29bade44317659dbe06f505e99dbe0', 378664), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\mscordaccore.dll': (1356640, '86c29a7b945525135de16c3dcb71e3b8517848c459cbb21395b352d4e6bba09c', 1356640), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\mscordaccore_amd64_amd64_10.0.1226.42308.dll': (1356640, '86c29a7b945525135de16c3dcb71e3b8517848c459cbb21395b352d4e6bba09c', 1356640), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\mscordbi.dll': (1237888, '753e92805f3886221f56dcfc07191ad7ee44235bf689db0490bdf777f25e9175', 1237888), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\mscorrc.dll': (133968, 'f0d8c7491d4659a4c5a4c00615255a60e05634f311162c2775a51e03c070c9e0', 133968), 'toolchain\\shared\\Microsoft.NETCore.App\\10.0.12\\msquic.dll': (536344, 'b7158d427b01c70483bb3d80c5211e387dd98e9471c8a70e4484d449de9157e8', 536344), 'toolchain\\host\\fxr\\10.0.12\\hostfxr.dll': (379688, '838591885c5396fb0588a3aedc2f3e841d3afc67570868b1bce615264005a44c', 379688), 'artifact\\DirectObserver.exe': (160768, None, 160768), 'artifact\\DirectObserver.dll': (-1, None, 1048576), 'artifact\\DirectObserver.runtimeconfig.json': (126, 'b7cb3a2e664fe814d052574cc0265d6a3c5a60d391b99ada2efc3c80cdaebdf3', 126), 'artifact\\DirectObserver.deps.json': (285, 'dcb770b630a44b4c23edebdce52f8b26cd53b6e6d0701c3f53928856d1ed8f27', 285), 'source\\direct_wsl_caller.py': (-1, None, 1048576), 'source\\result_validator_source.py': (-1, None, 1048576)}
DIRECT_SYNTHETIC_INPUTS = {'artifact\\SyntheticSubject.exe': (160768, None, 160768), 'artifact\\SyntheticSubject.dll': (-1, None, 1048576), 'artifact\\SyntheticSubject.runtimeconfig.json': (126, 'b7cb3a2e664fe814d052574cc0265d6a3c5a60d391b99ada2efc3c80cdaebdf3', 126), 'artifact\\SyntheticSubject.deps.json': (291, '4d24598c7fe6a1e8ecc685d3b42a1591da653eeb6b5be8491d6191466d0edfa4', 291)}
DIRECT_PRODUCT_INPUTS = {'product\\Authentication.Cli.exe': (8885248, '02993d94c5145f32274a8763f27d632e2dcc8e6a06d257551b1501eed9689cc7', 8885248), 'product\\msalruntime.dll': (2949656, '9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79', 2949656)}
def required_inputs(fixture):
    value = dict(DIRECT_BASE_INPUTS)
    value.update(DIRECT_SYNTHETIC_INPUTS if fixture else DIRECT_PRODUCT_INPUTS)
    return value

ROOT_WINDOWS = r"C:\Temp\azureauth-windows-slice-108\confidential-direct-v4"
ROOT_LINUX = "/mnt/c/Temp/azureauth-windows-slice-108/confidential-direct-v4"
PUBLIC_FIELDS = frozenset(("schema", "scope", "slot", "nonce", "protocolSha256",
    "callerSha256", "expectedExit", "productTimeoutSeconds", "soleLaunchIdentityPremiseAccepted",
    "targetedStopPremiseAccepted", "accountEffectsAdmitted", "calibrationAccepted", "pins", "privateReference"))
NATIVE_ID_FIELDS = frozenset(("volume", "index", "attributes", "created", "modified", "changed", "links"))
FIRST_HELD_MODE = "synthetic-first-held-v1"


def exact_object(value, keys):
    require(type(value) is dict and value.keys() == keys)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def reject_constant(_):
    raise SafeFailure()


def decode_document(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 262144)
    # The fixed accepted document is shallow. Bound nesting before the standard parser.
    depth = 0
    quoted = escaped = False
    for c in raw.decode("utf-8", "strict"):
        if quoted:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif c in "[{":
            depth += 1
            require(depth <= 8)
        elif c in "]}":
            depth -= 1
            require(depth >= 0)
    require(depth == 0 and not quoted)
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_object, parse_constant=reject_constant)


def linux_path(relative):
    require(type(relative) is str and relative and "/" not in relative and ":" not in relative)
    parts = relative.split("\\")
    require(all(p and p not in (".", "..") and not p.endswith((".", " ")) and
        all(33 <= ord(c) <= 126 for c in p) for p in parts))
    return ROOT_LINUX + "/" + "/".join(parts)


def native_identity(value, length):
    exact_object(value, NATIVE_ID_FIELDS)
    require(all(type(value[k]) is int for k in NATIVE_ID_FIELDS))
    require(0 <= value["volume"] <= 0xffffffff and 0 <= value["attributes"] <= 0xffffffff)
    require(0 < value["index"] <= 0xffffffffffffffff and value["links"] == 1)
    require(all(0 < value[k] <= 0x7fffffffffffffff for k in ("created", "modified", "changed")))
    require(type(length) is int and 0 < length <= 67108864)
    # Linux stat identifiers are not asserted to equal Windows file identities.
    # The native observer validates this tuple before publishing readiness.


class AcceptedDirectInputs:
    def __init__(self, path, digest):
        self.fds = []
        self.directories = {}
        self.files = {}
        self.plan = self.validator = self.request = None
        self.private_pin = None
        self.baseline_sha256 = None
        self.public_pins = {}
        self.active = self.closed = False
        self.original_start = time.monotonic()
        self.original_end = self.original_start + 155.0
        try:
            require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest))
            require(type(path) is str and re.fullmatch(re.escape(ROOT_LINUX) +
                r"/control/(?:R2|R3|R4|R9|R10|D0|D1|D2)-[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\.json", path))
            require(sys.dont_write_bytecode is True)
            self.admission = self.pin(path, -1, 262144, digest)
            data = decode_document(self.read(self.admission, 262144))
            slot, nonce = data["slot"], data["nonce"]
            require(slot in SLOTS and type(nonce) is str and path == ROOT_LINUX + "/control/" + slot + "-" + nonce + ".json")
            fixture = slot == "D0" or slot in FIXTURE_SLOTS
            exact_object(data, PUBLIC_FIELDS | ({"identityMode"} if fixture else set()))
            require(data["schema"] == ("confidential-direct-admission-v2" if fixture else "confidential-direct-admission-v1"))
            if fixture:
                require(data["identityMode"] == FIRST_HELD_MODE)
            require(data["scope"] == ("synthetic-direct" if fixture else "real-direct"))
            for name in ("soleLaunchIdentityPremiseAccepted", "targetedStopPremiseAccepted",
                    "accountEffectsAdmitted", "calibrationAccepted"):
                require(type(data[name]) is bool)
            require(data["soleLaunchIdentityPremiseAccepted"] and data["accountEffectsAdmitted"] is (not fixture))
            require((slot == "D0" or data["calibrationAccepted"]) and (not fixture or not data["targetedStopPremiseAccepted"]))
            require(type(data["expectedExit"]) is int and data["expectedExit"] in (0, 1))
            require(type(data["productTimeoutSeconds"]) is int and 1 <= data["productTimeoutSeconds"] <= 120)
            if fixture:
                require(data["expectedExit"] == (1 if slot == "D2" else 0) and data["productTimeoutSeconds"] == 5)
            require(all(type(data[k]) is str and re.fullmatch(r"[0-9a-f]{64}", data[k])
                for k in ("protocolSha256", "callerSha256")))
            expected = required_inputs(fixture)
            require(type(data["pins"]) is list and len(data["pins"]) == len(expected))
            total = 0
            hashes = {}
            for item in data["pins"]:
                exact_object(item, frozenset(("relative", "bytes", "sha256", "linuxIdentity" if fixture else "identity")))
                relative, size, sha = item["relative"], item["bytes"], item["sha256"]
                require(type(relative) is str and relative in expected)
                fixed_size, fixed_sha, maximum = expected.pop(relative)
                require(type(size) is int and 0 < size <= maximum and (fixed_size < 0 or size == fixed_size))
                require(type(sha) is str and re.fullmatch(r"[0-9a-f]{64}", sha) and (fixed_sha is None or sha == fixed_sha))
                if fixture:
                    admitted_identity = item["linuxIdentity"]
                    require(type(admitted_identity) is list and len(admitted_identity) == 9 and
                        all(type(x) is int for x in admitted_identity) and stat.S_ISREG(admitted_identity[2]) and
                        admitted_identity[5] == size and admitted_identity[8] == 1)
                else:
                    native_identity(item["identity"], size)
                total += size
                require(total <= 100663296)
                self.files[relative] = self.pin(linux_path(relative), size, maximum, sha)
                if fixture:
                    require(self.files[relative][1] == tuple(admitted_identity))
                self.public_pins[relative] = (size, sha)
                hashes[relative] = sha
            require(not expected and hashes[r"source\direct_wsl_caller.py"] == data["callerSha256"])
            require(os.path.abspath(__file__) == linux_path(r"source\direct_wsl_caller.py"))
            image = r"artifact\SyntheticSubject.exe" if fixture else r"product\Authentication.Cli.exe"
            self.plan = PublicPlan(slot=slot, nonce=nonce, product_image=ROOT_WINDOWS + "\\" + image,
                product_linux_image=linux_path(image), observer_image=ROOT_WINDOWS + r"\artifact\DirectObserver.exe",
                observer_linux_image=linux_path(r"artifact\DirectObserver.exe"), working_directory=ROOT_LINUX,
                record_directory=ROOT_LINUX + "/records/" + slot + "-" + nonce,
                product_sha256=hashes[image], caller_sha256=data["callerSha256"], protocol_sha256=data["protocolSha256"],
                expected_exit=data["expectedExit"], product_timeout_seconds=data["productTimeoutSeconds"],
                admission_path=ROOT_WINDOWS + "\\control\\" + slot + "-" + nonce + ".json", admission_sha256=digest)
            module = None
            if slot != "D0":
                helper = self.read(self.files[r"source\result_validator_source.py"], 1048576)
                require("_direct_result_validator" not in sys.modules)
                module = types.ModuleType("_direct_result_validator")
                module.__file__ = linux_path(r"source\result_validator_source.py")
                sys.modules[module.__name__] = module
                # Execute the exact held helper bytes after future source/call activation.
                # Its original false guard is retained; no text replacement or guard bypass.
                code = compile(helper, module.__file__, "exec", dont_inherit=True, optimize=0)
                exec(code, module.__dict__)
                self.validator = module
            reference = data["privateReference"]
            if fixture:
                require(reference is None)
                self.request = None if slot == "D0" else fixture_request(slot, module)
            else:
                exact_object(reference, frozenset(("relative", "bytes", "identity")))
                relative = reference["relative"]
                require(relative == "private\\" + slot + "-" + nonce + ".json")
                size = reference["bytes"]
                native_identity(reference["identity"], size)
                require(size <= 262144)
                private = self.pin(linux_path(relative), size, 262144, None)
                self.private_pin = private
                # The native observer validates and holds this reference before readiness.
                # No private content digest, selector or input value is published.
                private_data = decode_document(self.read(private, 262144))
                exact_object(private_data, frozenset(("schema", "slot", "nonce", "request")))
                require(private_data["schema"] == "confidential-direct-request-v1" and
                    private_data["slot"] == slot and private_data["nonce"] == nonce)
                self.request = private_request(private_data["request"], self.plan, module)
            if slot != "D0":
                arguments(self.plan, self.request, module)
            self.create_record_directory()
            self.before()
        except BaseException:
            self.close()
            raise

    def before(self):
        require(not self.closed and time.monotonic() < self.original_end)

    def accept_baseline(self, records, receipt):
        self.before()
        require(self.plan.slot == "D0" or self.plan.slot in FIXTURE_SLOTS)
        digest = receipt.get("nativeBaselineSha256")
        require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) and self.baseline_sha256 is None)
        value = decode_document(records.read_baseline(digest))
        exact_object(value, frozenset(("schema", "identityMode", "root", "original", "admissionSha256", "protocolSha256", "rows")))
        require(value["schema"] == "synthetic-native-baseline-v1" and value["identityMode"] == FIRST_HELD_MODE and
            value["root"] == ROOT_WINDOWS and value["original"] == self.plan.slot + "-" + self.plan.nonce and
            value["admissionSha256"] == self.plan.admission_sha256 and value["protocolSha256"] == self.plan.protocol_sha256)
        require(type(value["rows"]) is list and len(value["rows"]) == 200)
        for relative, row in zip(sorted(self.public_pins), value["rows"], strict=True):
            self.before()
            exact_object(row, frozenset(("relative", "bytes", "sha256", "identity")))
            require(row["relative"] == relative and type(row["bytes"]) is int and
                (row["bytes"], row["sha256"]) == self.public_pins[relative])
            native_identity(row["identity"], row["bytes"])
            require(row["identity"]["attributes"] & 0x410 == 0)
        self.baseline_sha256 = digest
        self.before()

    def hold_directory(self, path):
        self.before()
        require(path.startswith("/") and os.path.normpath(path) == path)
        if path in self.directories:
            return self.directories[path]
        if path != "/":
            self.hold_directory(os.path.dirname(path))
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.fds.append(fd)
        self.directories[path] = fd
        require(stat.S_ISDIR(os.fstat(fd).st_mode))
        return fd

    def create_record_directory(self):
        # One fresh owned directory, never a preexisting result set or a retry target.
        parent = self.hold_directory(ROOT_LINUX + "/records")
        self.before()
        leaf = self.plan.slot + "-" + self.plan.nonce
        os.mkdir(leaf, 0o700, dir_fd=parent)
        self.hold_directory(self.plan.record_directory)
        self.directories_unchanged()

    def directories_unchanged(self):
        # This binds the held directory chain without equating Linux and native IDs.
        # It is an ordinary-workstation check, not a hostile-OS race-proof claim.
        for path, fd in self.directories.items():
            self.before()
            held = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode) and
                (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino))

    def execution_image(self, role):
        self.before()
        require(self.active and role in ("observer", "product"))
        if role == "observer":
            relative = r"artifact\DirectObserver.exe"
            windows, projection = self.plan.observer_image, self.plan.observer_linux_image
        else:
            relative = r"artifact\SyntheticSubject.exe" if self.plan.slot == "D0" or self.plan.slot in FIXTURE_SLOTS else r"product\Authentication.Cli.exe"
            windows, projection = self.plan.product_image, self.plan.product_linux_image
        require(windows == ROOT_WINDOWS + "\\" + relative and projection == linux_path(relative) and
            projection.startswith(ROOT_LINUX + "/"))
        pin = self.files[relative]
        self.directories_unchanged()
        self.same(pin)
        require(stat.S_ISREG(pin[1][2]) and pin[1][2] & 0o111)
        # Content identity does not establish Linux exec eligibility. Check the exact
        # Windows-filesystem projection with effective-ID X_OK before each sole Popen.
        require(os.access(projection, os.X_OK, effective_ids=True, follow_symlinks=False))
        self.same(pin)
        self.directories_unchanged()
        self.before()
        return projection

    def pin(self, path, length, maximum, digest):
        self.before()
        parent = self.hold_directory(os.path.dirname(path))
        fd = os.open(os.path.basename(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        self.fds.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum and
            (length < 0 or before.st_size == length))
        pin = (fd, full9(before), parent, os.path.basename(path))
        if digest is not None:
            value = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                self.before()
                chunk = os.read(fd, min(65536, remaining))
                require(chunk)
                value.update(chunk)
                remaining -= len(chunk)
            require(os.read(fd, 1) == b"" and value.hexdigest() == digest)
        self.same(pin)
        os.lseek(fd, 0, os.SEEK_SET)
        return pin

    def same(self, pin):
        self.before()
        fd, identity, parent, name = pin
        require(full9(os.fstat(fd)) == identity and
            full9(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)

    def read(self, pin, maximum):
        self.same(pin)
        fd, identity, _, _ = pin
        require(identity[5] <= maximum)
        os.lseek(fd, 0, os.SEEK_SET)
        data = bytearray()
        while len(data) < identity[5]:
            self.before()
            chunk = os.read(fd, min(65536, identity[5] - len(data)))
            require(chunk)
            data.extend(chunk)
        require(os.read(fd, 1) == b"")
        self.same(pin)
        return bytes(data)

    def revalidate_private(self, plan, request, validator):
        self.before()
        require(self.active and plan is self.plan and request is self.request and validator is self.validator)
        if self.private_pin is None:
            require(plan.slot in FIXTURE_SLOTS)
            return
        # Readiness follows the observer's native private pin and request validation.
        # Re-read the same held Linux leaf, check its original full9, and compare only
        # in memory before launching the product. No private digest or field is output.
        value = decode_document(self.read(self.private_pin, 262144))
        exact_object(value, frozenset(("schema", "slot", "nonce", "request")))
        require(value["schema"] == "confidential-direct-request-v1" and
            value["slot"] == plan.slot and value["nonce"] == plan.nonce)
        require(private_request(value["request"], plan, validator) == request)

    def __enter__(self):
        self.before()
        require(not self.active)
        self.active = True
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        for fd in reversed(self.fds):
            try:
                os.close(fd)
            except OSError:
                pass
        self.fds.clear()
        # No erasure promise for Python strings/objects or kernel copies.


class AdmissionCatalog:
    current = None

    @staticmethod
    def load():
        require(AdmissionCatalog.current is None and len(sys.argv) == 4 and sys.argv[1] == "--admission")
        value = AcceptedDirectInputs(sys.argv[2], sys.argv[3])
        AdmissionCatalog.current = value
        return value.plan, value.request

    @staticmethod
    def result_validator():
        require(AdmissionCatalog.current is not None)
        return AdmissionCatalog.current.validator

    @staticmethod
    def hold_accepted_inputs(plan):
        value = AdmissionCatalog.current
        require(value is not None and plan is value.plan)
        return value

    @staticmethod
    def close():
        if AdmissionCatalog.current is not None:
            AdmissionCatalog.current.close()

PRIVATE_ROW_KEYS = frozenset(("profilePath", "tenantArgument", "exactResultTenant",
    "accountEmail", "scopes", "interactionAllowed", "timeoutSeconds", "outcome",
    "requiredInteraction", "lifetimePipe", "closeAfterMs", "requireCloseAfterLiveSample",
    "requirePersistenceUnconfirmed", "defaultAssociationIndependentlyAccepted"))


def private_request(row, plan, validator):
    # Row comes only from the held fixed private reference. Do not log, hash or format it.
    require(plan.slot in SLOTS - FIXTURE_SLOTS - {"D0"})
    require(type(row) is dict and row.keys() == PRIVATE_ROW_KEYS)
    for key in ("interactionAllowed", "lifetimePipe", "requireCloseAfterLiveSample",
            "requirePersistenceUnconfirmed", "defaultAssociationIndependentlyAccepted"):
        require(type(row[key]) is bool)
    require(row["requireCloseAfterLiveSample"] is False)
    require(type(row["timeoutSeconds"]) is int and row["timeoutSeconds"] == plan.product_timeout_seconds)
    require(type(row["scopes"]) is list)
    request = PrivateRequest(
        profile_path=row["profilePath"], tenant_argument=row["tenantArgument"],
        expected=validator.Expected(email=row["accountEmail"], tenant=row["exactResultTenant"],
            scopes=tuple(row["scopes"]), interaction_allowed=row["interactionAllowed"],
            outcome=row["outcome"], required_interaction=row["requiredInteraction"]),
        lifetime_pipe=row["lifetimePipe"], close_after_ms=row["closeAfterMs"],
        default_association_independently_accepted=row["defaultAssociationIndependentlyAccepted"])
    require(row["outcome"] != "success" or row["requirePersistenceUnconfirmed"] is True)
    arguments(plan, request, validator)
    return request


def identity(plan, kind):
    value = {"schema": "direct-wsl-2", "kind": kind, "slot": plan.slot, "nonce": plan.nonce,
        "productImage": plan.product_image, "productSha256": plan.product_sha256,
        "callerSha256": plan.caller_sha256, "protocolSha256": plan.protocol_sha256,
        "expectedExit": plan.expected_exit, "productTimeoutSeconds": plan.product_timeout_seconds}
    if (plan.slot == "D0" or plan.slot in FIXTURE_SLOTS) and kind != "reservation":
        require(AdmissionCatalog.current.baseline_sha256 is not None)
        value["nativeBaselineSha256"] = AdmissionCatalog.current.baseline_sha256
    return value


def arguments(plan, request, validator):
    require(type(plan) is PublicPlan and type(request) is PrivateRequest)
    require(plan.slot in SLOTS and re.fullmatch(r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}", plan.nonce))
    require(type(plan.expected_exit) is int and plan.expected_exit in (0, 1))
    require(type(plan.product_timeout_seconds) is int and 1 <= plan.product_timeout_seconds <= 120)
    require(all(re.fullmatch(r"[0-9a-f]{64}", x) for x in
        (plan.product_sha256, plan.caller_sha256, plan.protocol_sha256)))
    require(all(validator.direct_token(x) and x.startswith("C:\\") and len(x) <= 1024
        for x in (plan.product_image, plan.observer_image)))
    require(all(type(x) is str and x.startswith("/") and "\x00" not in x
        for x in (plan.product_linux_image, plan.observer_linux_image, plan.working_directory, plan.record_directory)))
    validator.valid_expected(request.expected)  # Mandatory private preflight before either process launch.
    expected = request.expected
    require(plan.expected_exit == (0 if expected.outcome == "success" else 1))
    require(validator.direct_token(request.profile_path) and 3 <= len(request.profile_path) <= 32767
        and re.match(r"[A-Za-z]:\\", request.profile_path))
    require(request.tenant_argument == "common" or
        validator.GUID.fullmatch(request.tenant_argument) is not None and
        type(expected.tenant) is str and request.tenant_argument.lower() == expected.tenant.lower())
    require(not any(x.endswith("/.default") for x in expected.scopes)
        or request.default_association_independently_accepted is True)
    require(type(request.lifetime_pipe) is bool)
    require(request.close_after_ms is None or type(request.close_after_ms) is int and request.lifetime_pipe
        and 0 <= request.close_after_ms < plan.product_timeout_seconds * 1000)
    # R9/D2 require a deliberate close. This does not prove real provider work was pending.
    require((plan.slot in CLOSE_SLOTS) == (request.close_after_ms is not None))
    if plan.slot in FIXTURE_SLOTS:
        require(plan.product_timeout_seconds == 5 and request == fixture_request(plan.slot, validator))
    else:
        require(request.fixture_case is None)
    args = [plan.product_image, "authenticate", "--protocol", "1", "--profile", request.profile_path,
        "--account-email", expected.email, "--interaction",
        "interactive-if-needed" if expected.interaction_allowed else "non-interactive-only",
        "--tenant", request.tenant_argument, "--timeout-seconds", str(plan.product_timeout_seconds),
        "--telemetry", "off"]
    for scope in expected.scopes:
        args.extend(("--scope", scope))
    if request.lifetime_pipe:
        args.append("--cancel-on-stdin-close")
    if plan.slot in FIXTURE_SLOTS:
        args.extend(("--synthetic-direct", plan.slot))
    require(all(validator.direct_token(x) for x in args) and len(args) <= 161 and
        sum(map(len, args)) + len(args) - 1 <= 32766)
    return args


def full9(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
        st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


class Records:
    def __init__(self, directory):
        self.fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.reads = 0
        self.written = set()
        self.baseline_read = False

    def close(self):
        os.close(self.fd)

    def publish(self, name, value):
        require(name in ("reservation.json", "intent.json", "terminal.json", "stop", "close-anchor-request") and name not in self.written)
        self.written.add(name)  # No retry after any partial write/publication failure.
        raw = b"" if name in ("stop", "close-anchor-request") else json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        require(len(raw) <= 4096)
        temporary = name + ".pending"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=self.fd)
        try:
            # One bounded write, no append or raw-result sink. A short write fails.
            require(os.write(fd, raw) == len(raw))
            os.fsync(fd)
        finally:
            os.close(fd)
        # Atomic exclusive publication. A transient two-link observation fails closed;
        # interoperability/hard-link support is an outstanding controlled prerequisite.
        os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=self.fd)
        os.fsync(self.fd)

    def require_anchor_names_absent(self):
        for name in ("close-anchor-request", "close-anchor-request.pending",
                     "close-anchor-ack", "close-anchor-ack.pending"):
            try:
                os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise SafeFailure()

    def anchor_ack(self):
        self.reads += 1
        require(self.reads <= 17000)
        try:
            fd = os.open("close-anchor-ack", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=self.fd)
        except FileNotFoundError:
            return False
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == 0)
            require(os.read(fd, 1) == b"" and full9(before) == full9(os.fstat(fd)) and
                full9(before) == full9(os.stat("close-anchor-ack", dir_fd=self.fd, follow_symlinks=False)))
            return True
        finally:
            os.close(fd)

    def read(self, name):
        require(name in ("readiness.json", "observer-final.json"))
        self.reads += 1
        require(self.reads <= 17000)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 4096)
            raw = os.read(fd, 4097)
            require(full9(before) == full9(os.fstat(fd)) and len(raw) == before.st_size)
        finally:
            os.close(fd)
        def pairs(items):
            result = {}
            for key, item in items:
                require(key not in result)
                result[key] = item
            return result
        def bad_constant(_):
            raise SafeFailure()
        # Record caps are 4 KiB; only the exact shallow scalar schema is subsequently accepted.
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=bad_constant)

    def read_baseline(self, digest):
        require(not self.baseline_read)
        self.baseline_read = True
        self.reads += 1
        require(self.reads <= 17000)
        name = "native-baseline.json"
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 262144)
            raw = bytearray()
            while len(raw) < before.st_size:
                AdmissionCatalog.current.before()
                chunk = os.read(fd, min(65536, before.st_size - len(raw)))
                require(chunk)
                raw.extend(chunk)
            require(os.read(fd, 1) == b"" and full9(before) == full9(os.fstat(fd)) and
                full9(before) == full9(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) and
                hashlib.sha256(raw).hexdigest() == digest)
            return bytes(raw)
        finally:
            os.close(fd)


class PrivateCapture:
    def __init__(self, process, stdout_cap, stderr_cap, selector):
        self.process = process
        self.streams = (process.stdout, process.stderr)
        self.caps = (stdout_cap, stderr_cap)
        self.buffers = (bytearray(), bytearray())
        self.eof = [False, False]
        self.calls = [0, 0]
        self.received_at = None
        self.selector = selector
        for index, stream in enumerate(self.streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (self, index))

    def read(self, index):
        self.calls[index] += 1
        require(self.calls[index] <= self.caps[index] + 1024)
        stream, buffer = self.streams[index], self.buffers[index]
        try:
            data = os.read(stream.fileno(), min(65536, self.caps[index] - len(buffer) + 1))
        except BlockingIOError:
            return
        if not data:
            self.eof[index] = True
            if index == 0:
                self.received_at = datetime.now(timezone.utc)
            self.selector.unregister(stream)
            stream.close()
            return
        require(len(buffer) + len(data) <= self.caps[index])
        buffer.extend(data)

    def complete(self):
        return all(self.eof) and self.process.poll() is not None

    def close(self):
        for stream in self.streams:
            if not stream.closed:
                try:
                    self.selector.unregister(stream)
                except (KeyError, ValueError):
                    pass
                stream.close()
        for buffer in self.buffers:
            buffer[:] = b"\x00" * len(buffer)
        # Best effort for these bytearrays only, not an erasure promise for Python or OS copies.


def pump(selector, seconds):
    for event, _ in selector.select(max(0.0, min(seconds, 0.01))):
        capture, index = event.data
        capture.read(index)


def match_record(value, plan, kind, extras=frozenset()):
    expected_identity = identity(plan, kind)
    require(type(value) is dict and value.keys() == expected_identity.keys() | extras)
    for key, expected in expected_identity.items():
        require(type(value[key]) is type(expected) and value[key] == expected)


def validate_observer(value, plan):
    match_record(value, plan, "observer-final", FINAL_EXTRA)
    booleans = FINAL_EXTRA - frozenset(("observerJobTotal", "fault", "nativeEvidence", "callbacks",
        "eventsLost", "logBuffersLost", "realTimeBuffersLost", "nativeExit", "nativeDurationMs", "anchorToEndUpperBoundMs"))
    require(all(type(value[key]) is bool for key in booleans))
    for key in ("observerJobTotal", "callbacks", "eventsLost", "logBuffersLost", "realTimeBuffersLost", "nativeExit", "nativeDurationMs", "anchorToEndUpperBoundMs"):
        require(type(value[key]) is int)
    calibration = plan.slot == "D0"
    require(value["passed"] and value["workerExited"] and value["observerJobZero"] and
        value["observerJobTotal"] == (3 if calibration else 1))
    require(value["fault"] == "None" and value["nativeEvidence"] == ("calibration-creation-handles" if calibration else "matched-native-events") and
        value["productLifetimeKnown"] and value["productInObserverJob"] is calibration)
    require(value["traceStopped"] and value["traceDrained"] and value["traceZeroLoss"] and
        all(value[key] == 0 for key in ("eventsLost", "logBuffersLost", "realTimeBuffersLost")))
    require(not value["observerStopAttempted"] and not value["targetStopAttempted"] and
        not value["observerStopSucceeded"] and 0 <= value["callbacks"] <= 65536)
    require(value["nativeExit"] == plan.expected_exit and
        0 <= value["nativeDurationMs"] <= plan.product_timeout_seconds * 1000 + 1000)
    require(value["scenarioAccepted"] is False)
    if plan.slot in CLOSE_SLOTS:
        require(value["anchorAckPublished"] and value["endByAnchorDeadline"] and
            1 <= value["anchorToEndUpperBoundMs"] <= 1000)
    else:
        require(not value["anchorAckPublished"] and not value["endByAnchorDeadline"] and
            value["anchorToEndUpperBoundMs"] == -1)



def run_calibration(plan):
    require(plan.slot == "D0")
    with AdmissionCatalog.hold_accepted_inputs(plan):
        records = Records(plan.record_directory)
        selector = selectors.DefaultSelector()
        supervisor = None
        outer_end = AdmissionCatalog.current.original_end
        try:
            reservation = identity(plan, "reservation")
            reservation.update({"executionComplete": False, "scenarioAccepted": False})
            records.publish("reservation.json", reservation)
            child = subprocess.Popen([plan.observer_image, "--supervisor", plan.slot, plan.nonce,
                plan.admission_path, plan.admission_sha256],
                executable=AdmissionCatalog.current.execution_image("observer"),
                cwd=plan.working_directory, env=None, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            supervisor = PrivateCapture(child, 0, 0, selector)
            result = None
            for _ in range(15500):
                require(time.monotonic() < outer_end)
                pump(selector, 0.01)
                if result is None:
                    result = records.read("observer-final.json")
                if supervisor.complete() and result is not None:
                    break
            require(supervisor.complete() and child.returncode == 0 and result is not None)
            AdmissionCatalog.current.accept_baseline(records, result)
            validate_observer(result, plan)
            terminal = identity(plan, "terminal")
            terminal.update({"executionComplete": True, "transportComplete": True,
                "calibrationPlumbingComplete": True, "nativeEvidence": "calibration-creation-handles",
                "observerJobZero": True, "observerJobTotal": 3, "productInObserverJob": True,
                "scenarioAccepted": False, "nativeCancellationLatencyEstablished": False})
            records.publish("terminal.json", terminal)
            require(time.monotonic() < outer_end)
            return 0
        except BaseException:
            cleanup_end = min(outer_end, time.monotonic() + 10.0)
            try:
                records.publish("stop", None)
            except BaseException:
                pass
            for _ in range(1000):
                if time.monotonic() >= cleanup_end:
                    break
                try:
                    pump(selector, 0.01)
                    if supervisor is not None and supervisor.complete():
                        break
                except BaseException:
                    break
            return 1  # A pending reservation is not lifetime or calibration acceptance.
        finally:
            if supervisor is not None:
                supervisor.close()
            selector.close()
            records.close()


def run(plan, request, validator):
    args = arguments(plan, request, validator)
    with AdmissionCatalog.hold_accepted_inputs(plan):
        records = Records(plan.record_directory)
        selector = selectors.DefaultSelector()
        supervisor = product = None
        writer = read_end = None
        started = AdmissionCatalog.current.original_start
        outer_end = AdmissionCatalog.current.original_end
        close_began = transport_done = anchor_began = None
        ack_attempts = 0
        pre_close_ack_observed = writer_close_completed = False
        launch_began = None
        safe_result = None
        try:
            if plan.slot in CLOSE_SLOTS:
                records.require_anchor_names_absent()
            reservation = identity(plan, "reservation")
            reservation.update({"executionComplete": False, "scenarioAccepted": False})
            records.publish("reservation.json", reservation)
            # Explicit Windows argv0 plus Linux executable projection through normal WSL interop; no added shell or controller process.
            child = subprocess.Popen([plan.observer_image, "--supervisor", plan.slot, plan.nonce,
                plan.admission_path, plan.admission_sha256],
                executable=AdmissionCatalog.current.execution_image("observer"), cwd=plan.working_directory, env=None,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            supervisor = PrivateCapture(child, 0, 0, selector)
            readiness = None
            for _ in range(500):
                require(time.monotonic() < started + 5.0 and child.poll() is None)
                pump(selector, 0.01)
                readiness = records.read("readiness.json")
                if readiness is not None:
                    break
            require(readiness is not None)
            if plan.slot in FIXTURE_SLOTS:
                AdmissionCatalog.current.accept_baseline(records, readiness)
            match_record(readiness, plan, "readiness")
            AdmissionCatalog.current.revalidate_private(plan,request,validator)
            ready_at = time.monotonic()
            records.publish("intent.json", identity(plan, "intent"))
            require(time.monotonic() < min(started + 7.0, ready_at + 2.0))
            require(time.monotonic() + 121.0 + 9.0 + 8.0 <= started + 145.0)
            read_end, writer = os.pipe2(os.O_CLOEXEC)
            if not request.lifetime_pipe:
                os.close(writer)
                writer = None
            launch_began = time.monotonic()
            child = subprocess.Popen(args, executable=AdmissionCatalog.current.execution_image("product"),
                cwd=plan.working_directory, env=None, stdin=read_end,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            os.close(read_end)
            read_end = None
            product = PrivateCapture(child, 1048576, 8192, selector)
            require(time.monotonic() < min(started + 7.0, ready_at + 2.0))
            capture_end = min(launch_began + 135.0, outer_end)
            normal_transport_end = launch_began + plan.product_timeout_seconds + 1.0
            observer_final = None
            for _ in range(15500):
                now = time.monotonic()
                require(now < outer_end and (product.complete() or now < capture_end))
                if request.close_after_ms is not None and close_began is None and now >= launch_began + request.close_after_ms / 1000:
                    # Proxy liveness is recorded only as transport state, not provider/native liveness.
                    require(child.poll() is None and writer is not None)
                    if anchor_began is None:
                        require(now + 1.25 <= min(normal_transport_end, capture_end, outer_end))
                        anchor_began = time.monotonic()
                        records.publish("close-anchor-request", None)
                    require(time.monotonic() < anchor_began + 0.250 and ack_attempts < 25)
                    ack_attempts += 1
                    if records.anchor_ack():
                        require(time.monotonic() < anchor_began + 0.250)
                        pre_close_ack_observed = True
                        close_began = time.monotonic()
                        closing = writer
                        writer = None
                        os.close(closing)  # No retry; cleanup close cannot qualify.
                        writer_close_completed = True
                pump(selector, 0.01)
                if product.complete() and transport_done is None:
                    transport_done = time.monotonic()
                    require(transport_done <= normal_transport_end)
                    if close_began is not None:
                        require(transport_done <= close_began + 1.0)
                    safe_result = validator.validate_complete(bytes(product.buffers[0]), bytes(product.buffers[1]),
                        child.returncode, True, request.expected, product.received_at)
                    require(type(safe_result) is dict and safe_result.get("protocolValid") is True and
                        safe_result.get("expectationMatched") is True)
                    require(safe_result.keys() == {"protocolValid", "outcome", "expectationMatched",
                        "successMetadataValidated", "apiRoute", "persistenceUnconfirmed"})
                    require(safe_result["outcome"] == request.expected.outcome and
                        safe_result["apiRoute"] in (None, "silent", "interactive") and
                        type(safe_result["successMetadataValidated"]) is bool and
                        type(safe_result["persistenceUnconfirmed"]) is bool)
                if observer_final is None:
                    observer_final = records.read("observer-final.json")
                if product.complete() and supervisor.complete() and observer_final is not None:
                    break
            require(product.complete() and supervisor.complete() and supervisor.process.returncode == 0)
            require(close_began is not None if request.close_after_ms is not None else True)
            require(observer_final is not None and safe_result is not None)
            validate_observer(observer_final, plan)
            terminal = identity(plan, "terminal")
            terminal.update({"executionComplete": True, "transportComplete": True, "protocolValid": True,
                "expectationMatched": True, "nativeEvidence": "matched-native-events", "observerJobZero": True,
                "productInObserverJob": False, "scenarioAccepted": False,
                "scenarioWitnessesPending": True, "outcome": safe_result["outcome"],
                "apiRoute": safe_result["apiRoute"], "persistenceUnconfirmed": safe_result["persistenceUnconfirmed"],
                "lifetimeWriterClosed": close_began is not None,
                "transportCloseToCompletionMs": -1 if close_began is None else
                    int((transport_done - close_began) * 1000 + 0.999999),
                "preCloseAckObserved": pre_close_ack_observed,
                "writerCloseCompleted": writer_close_completed,
                "nativeCloseToExitUpperBoundEstablished": plan.slot in CLOSE_SLOTS and pre_close_ack_observed and
                    writer_close_completed and observer_final["endByAnchorDeadline"],
                "nativeTimingBasis": "pre-close-native-anchor" if plan.slot in CLOSE_SLOTS and
                    pre_close_ack_observed and writer_close_completed and observer_final["endByAnchorDeadline"] else "unavailable",
                "nativeCancellationLatencyEstablished": False})
            # Parse returns a fixed allowlist; never merge a caller-controlled arbitrary dictionary.
            records.publish("terminal.json", terminal)
            require(time.monotonic() < outer_end)
            return 0  # Plumbing complete only; scenario acceptance is explicitly false.
        except BaseException:
            # No str/repr/traceback, raw fallback, PID kill, Linux signal or retry.
            cleanup_end = min(outer_end, time.monotonic() + 10.0)
            if writer is not None:
                closing = writer
                writer = None
                try:
                    os.close(closing)
                except OSError:
                    pass
            try:
                records.publish("stop", None)
            except BaseException:
                pass
            for _ in range(1000):
                if time.monotonic() >= cleanup_end:
                    break
                try:
                    pump(selector, 0.01)
                    if supervisor is not None and supervisor.complete() and (product is None or product.complete()):
                        break
                except BaseException:
                    break
            # Reservation remains open. Native product, trace and observer closure must
            # come from their witnesses; Linux exit/EOF and observer Job zero cannot replace them.
            return 1
        finally:
            if writer is not None:
                os.close(writer)
            if read_end is not None:
                os.close(read_end)
            if product is not None:
                product.close()
            if supervisor is not None:
                supervisor.close()
            selector.close()
            records.close()


def main():
    try:
        plan, request = AdmissionCatalog.load()
        if plan.slot == "D0":
            return run_calibration(plan)
        return run(plan, request, AdmissionCatalog.result_validator())
    except BaseException:
        return 1
    finally:
        AdmissionCatalog.close()


if __name__ == "__main__":
    raise SystemExit(main())
