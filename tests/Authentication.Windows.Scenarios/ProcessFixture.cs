using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Authentication.Windows.Scenarios;

// Finite, sequential child scenarios inside the existing outer experiment Job.
// This fixture never starts a shell, changes account state, or breaks out of that Job.
internal sealed partial class ProcessFixture : IDisposable
{
    private static int safetyStopped;
    private nint inputRead, inputWrite, outputRead, outputWrite, errorRead, errorWrite, process;
    private Task<byte[]>? output, error;
    private readonly Stopwatch elapsed = Stopwatch.StartNew();
    private readonly bool blockedOutput, blockedError;
    private bool finished;
    private bool finalizationAttempted;
    private bool stopAttempted;
    internal string DirectoryPath { get; }
    internal bool Forced { get; private set; }
    internal uint ExitCode { get; private set; }
    internal double Seconds => elapsed.Elapsed.TotalSeconds;
    internal long ExitObservedTimestamp { get; private set; }
    internal long WriterCloseBefore { get; private set; }
    internal long WriterCloseAfter { get; private set; }
    internal long BufferedObservedTimestamp { get; private set; }
    internal long EntryTimestamp => long.Parse(File.ReadAllText(Path.Combine(DirectoryPath, "entered")), CultureInfo.InvariantCulture);
    internal bool Exited
    {
        get
        {
            if (process == 0) return false;
            var wait = WaitForSingleObject(process, 0);
            if (wait is not (0 or 258)) throw StopSuite("child-state");
            if (wait == 0 && ExitObservedTimestamp == 0) ExitObservedTimestamp = TimeProvider.System.GetTimestamp();
            return wait == 0;
        }
    }
    internal byte[] Output { get; private set; } = [];
    internal byte[] Error { get; private set; } = [];
    internal uint BufferedOutput { get; private set; }
    internal uint DiagnosticPrefill { get; private set; }

    internal unsafe ProcessFixture(string scenario)
    {
        RequireActiveSuite();
        if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("Windows scenario required.");
        if (scenario is not ("help" or "malformed" or "success" or "file-stdin" or "closed-stdin"
            or "close-pending" or "unused-stdin" or "data-close" or "deadline"
            or "broken-output" or "blocked-output" or "blocked-diagnostics"))
            throw new InvalidOperationException("Unallocated child scenario.");

        blockedOutput = scenario == "blocked-output";
        blockedError = scenario == "blocked-diagnostics";
        DirectoryPath = Path.Combine(Path.GetTempPath(), "process-" + scenario);
        if (Directory.Exists(DirectoryPath)) throw new InvalidOperationException("Scenario already reserved.");
        Directory.CreateDirectory(DirectoryPath);
        File.WriteAllText(Path.Combine(DirectoryPath, "reserved.json"),
            JsonSerializer.Serialize(new { scenario, utc = DateTimeOffset.UtcNow }));

        try
        {
            Pipe(out inputRead, out inputWrite);
            Pipe(out outputRead, out outputWrite);
            Pipe(out errorRead, out errorWrite);
            var profilePath = Path.Combine(DirectoryPath, "profile.json");
            File.WriteAllText(profilePath, ProcessChild.Profile, new UTF8Encoding(false));
            if (scenario == "file-stdin")
            {
                Close(ref inputRead);
                Close(ref inputWrite);
                using var file = File.OpenHandle(profilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (DuplicateHandle(new nint(-1), file.DangerousGetHandle(), new nint(-1),
                    out inputRead, 0, 0, 2) == 0) throw Failure();
            }
            if (scenario is "closed-stdin" or "unused-stdin") Close(ref inputWrite);
            if (scenario == "broken-output") Close(ref outputRead);
            // The successful-result case also proves a broken diagnostic sink is ignored.
            if (scenario == "success") Close(ref errorRead);
            if (blockedError)
            {
                if (GetNamedPipeInfo(errorRead, null, out var capacity, null, null) == 0
                    || capacity is < 1 or > 65536) throw Failure();
                Write(errorWrite, Enumerable.Repeat((byte)'D', checked((int)capacity)).ToArray());
                DiagnosticPrefill = capacity;
            }

            var cli = scenario is "help" or "malformed";
            var assembly = cli
                ? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
                    "../../../../../src/Authentication.Cli/bin/Release/net10.0-windows/win-x64/Authentication.Cli.dll"))
                : Path.Combine(AppContext.BaseDirectory, "Authentication.Windows.Scenarios.dll");
            var arguments = new List<string> { assembly };
            if (!cli) arguments.AddRange(["--scenario-child", scenario]);
            if (scenario == "help") arguments.Add("--help");
            else if (scenario == "malformed") arguments.AddRange(["authenticate", "--protocol", "SYNTHETIC_INVALID_VERSION"]);
            else
            {
                arguments.AddRange(["authenticate", "--protocol", "1", "--profile", profilePath,
                    "--account-email", ProcessChild.Email, "--scope", ProcessChild.Scope,
                    "--interaction", "non-interactive-only", "--tenant", ProcessChild.Tenant,
                    "--timeout-seconds", scenario is "deadline" or "blocked-output" or "blocked-diagnostics" ? "1" : "4"]);
                if (scenario is "file-stdin" or "closed-stdin" or "close-pending" or "data-close")
                    arguments.Add("--cancel-on-stdin-close");
                if (scenario is "success" or "blocked-diagnostics") arguments.AddRange(["--telemetry", "stderr"]);
            }
            Start(arguments);
            Close(ref inputRead);
            Close(ref outputWrite);
            Close(ref errorWrite);
            if (!blockedOutput) output = Capture(ref outputRead);
            if (!blockedError) error = Capture(ref errorRead);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal bool Marked(string name) => File.Exists(Path.Combine(DirectoryPath, name));

    internal async Task<bool> WaitForMarkerAsync(string name)
    {
        while (!Marked(name) && !Exited && Seconds < 6) await Task.Delay(10);
        return Marked(name);
    }

    internal void CloseInput(bool payload = false)
    {
        if (payload) Write(inputWrite, "SYNTHETIC_IGNORED_STDIN_DATA\n"u8.ToArray());
        WriterCloseBefore = TimeProvider.System.GetTimestamp();
        Close(ref inputWrite);
        WriterCloseAfter = TimeProvider.System.GetTimestamp();
    }

    internal async Task<bool> ObserveBufferedOutputAsync()
    {
        while (!Exited && Seconds < 6)
        {
            if (!TryAvailable(outputRead, out var available)) break;
            if (available > 0)
            {
                BufferedOutput = available;
                BufferedObservedTimestamp = TimeProvider.System.GetTimestamp();
                return true;
            }
            await Task.Delay(10);
        }
        return false;
    }

    internal async Task FinishAsync()
    {
        while (!Exited && Seconds < 6) await Task.Delay(10);
        StopIfNeeded();
        await FinalizeEvidenceAsync();
    }

    private async Task FinalizeEvidenceAsync()
    {
        if (finished) return;
        if (finalizationAttempted) throw StopSuite("evidence-finalization");
        finalizationAttempted = true;
        try
        {
            if (!Exited) throw StopSuite("child-quiescence");
            output ??= Capture(ref outputRead);
            error ??= Capture(ref errorRead);
            var captures = await Task.WhenAll(output, error).WaitAsync(
                TimeSpan.FromSeconds(Math.Max(0.001, 8 - Seconds)));
            Output = captures[0];
            Error = captures[1];
            if (GetExitCodeProcess(process, out var code) == 0) throw StopSuite("child-exit-code");
            ExitCode = code;
            File.WriteAllBytes(Path.Combine(DirectoryPath, "stdout.bin"), Output);
            File.WriteAllBytes(Path.Combine(DirectoryPath, "stderr.bin"), Error);
            using var receipt = new FileStream(Path.Combine(DirectoryPath, "result.json"),
                FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            JsonSerializer.Serialize(receipt, new
            {
                exitCode = ExitCode, forced = Forced, seconds = Seconds, quiescent = Exited,
                stdoutBytes = Output.Length, stderrBytes = Error.Length, bufferedOutput = BufferedOutput,
                diagnosticPrefill = DiagnosticPrefill,
                timestampFrequency = TimeProvider.System.TimestampFrequency,
                entryTimestamp = Marked("entered") ? EntryTimestamp : (long?)null,
                writerCloseBefore = WriterCloseBefore, writerCloseAfter = WriterCloseAfter,
                bufferedObservedTimestamp = BufferedObservedTimestamp, exitObservedTimestamp = ExitObservedTimestamp,
            });
            receipt.Flush(true);
            finished = true;
        }
        catch (Exception) { throw StopSuite("evidence-finalization"); }
    }

    private void StopIfNeeded()
    {
        if (process == 0 || Exited) return;
        if (stopAttempted) throw StopSuite("child-quiescence");
        stopAttempted = true;
        Forced = true;
        if (TerminateProcess(process, 91) == 0 && !Exited) throw StopSuite("child-termination");
        if (WaitForSingleObject(process, 2000) != 0) throw StopSuite("child-quiescence");
    }

    public void Dispose()
    {
        StopIfNeeded();
        Close(ref inputRead); Close(ref inputWrite); Close(ref outputWrite); Close(ref errorWrite);
        if (process != 0)
        {
            // Assertion failure still retains the same bounded exit/capture
            // evidence as the ordinary path. Never label loader failure useful red.
            FinalizeEvidenceAsync().GetAwaiter().GetResult();
        }
        else if (!finished)
        {
            Close(ref outputRead); Close(ref errorRead);
            throw StopSuite("child-start");
        }
        Close(ref outputRead); Close(ref errorRead); Close(ref process);
    }

    private static Task<byte[]> Capture(ref nint ownedHandle)
    {
        if (ownedHandle == 0) return Task.FromResult(Array.Empty<byte>());
        var handle = new SafeFileHandle(ownedHandle, true);
        ownedHandle = 0;
        var completion = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        new Thread(() =>
        {
            try
            {
                using var stream = new FileStream(handle, FileAccess.Read, 4096, false);
                using var bytes = new MemoryStream();
                var buffer = new byte[4096];
                int count;
                while ((count = stream.Read(buffer)) != 0)
                {
                    if (bytes.Length + count > 524288) throw new IOException("Fixture capture exceeded its bound.");
                    bytes.Write(buffer, 0, count);
                }
                completion.TrySetResult(bytes.ToArray());
            }
            catch (Exception exception) { handle.Dispose(); completion.TrySetException(exception); }
        }) { IsBackground = true }.Start();
        return completion.Task;
    }

    private unsafe void Start(List<string> arguments)
    {
        RequireActiveSuite();
        const string executable = @"C:\Program Files\dotnet\dotnet.exe";
        var command = (string.Join(' ', new[] { executable }.Concat(arguments).Select(Quote)) + '\0').ToCharArray();
        var environment = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = @"C:\Windows", ["WINDIR"] = @"C:\Windows", ["OS"] = "Windows_NT",
            ["PROCESSOR_ARCHITECTURE"] = "AMD64", ["PATH"] = @"C:\Program Files\dotnet;C:\Windows\System32",
            ["DOTNET_ROOT"] = @"C:\Program Files\dotnet", ["DOTNET_ROLL_FORWARD"] = "Disable",
            ["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1", ["TESTINGPLATFORM_TELEMETRY_OPTOUT"] = "1",
            ["DOTNET_NOLOGO"] = "1", ["TEMP"] = DirectoryPath, ["TMP"] = DirectoryPath,
            ["USERPROFILE"] = DirectoryPath, ["APPDATA"] = DirectoryPath, ["LOCALAPPDATA"] = DirectoryPath,
        };
        var block = (string.Join('\0', environment.Select(pair => pair.Key + "=" + pair.Value)) + "\0\0").ToCharArray();
        nint[] handles = [inputRead, outputWrite, errorWrite];
        foreach (var handle in handles) if (SetHandleInformation(handle, 1, 1) == 0) throw Failure();
        nuint size = 0;
        InitializeProcThreadAttributeList(null, 1, 0, ref size);
        if (size is 0 or > 65536) throw Failure();
        var attributes = NativeMemory.Alloc(size);
        var initialized = false;
        try
        {
            if (InitializeProcThreadAttributeList(attributes, 1, 0, ref size) == 0) throw Failure();
            initialized = true;
            fixed (nint* list = handles)
            fixed (char* commandPointer = command)
            fixed (char* environmentPointer = block)
            {
                if (UpdateProcThreadAttribute(attributes, 0, 0x20002, list,
                    (nuint)(handles.Length * sizeof(nint)), null, null) == 0) throw Failure();
                var startup = new StartupInfoEx
                {
                    Info = new StartupInfo { Size = (uint)sizeof(StartupInfoEx), Flags = 0x100,
                        Input = inputRead, Output = outputWrite, Error = errorWrite },
                    Attributes = attributes,
                };
                RequireActiveSuite();
                if (CreateProcessW(executable, commandPointer, null, null, 1, 0x08080400,
                    environmentPointer, DirectoryPath, ref startup, out var information) == 0) throw Failure();
                process = information.Process;
                CloseHandle(information.Thread);
                File.WriteAllText(Path.Combine(DirectoryPath, "started.json"), JsonSerializer.Serialize(new
                {
                    pid = information.ProcessId, executable, arguments, environment, utc = DateTimeOffset.UtcNow,
                }));
            }
        }
        finally
        {
            if (initialized) DeleteProcThreadAttributeList(attributes);
            NativeMemory.Free(attributes);
        }
    }

    private static unsafe bool TryAvailable(nint pipe, out uint available) =>
        PeekNamedPipe(pipe, null, 0, null, out available, null) != 0;

    private static string Quote(string argument)
    {
        // All fixture values are fixed words or owned Windows paths, with no quote
        // or trailing separator. Refuse additions requiring a broader quoting grammar.
        if (argument.Contains('"') || argument.EndsWith('\\') || argument.Contains('\0')) throw Failure();
        return '"' + argument + '"';
    }

    private static unsafe void Pipe(out nint reader, out nint writer)
    {
        if (CreatePipe(out reader, out writer, null, 4096) == 0) { reader = writer = 0; throw Failure(); }
    }

    private static unsafe void Write(nint handle, byte[] bytes)
    {
        fixed (byte* data = bytes)
            if (WriteFile(handle, data, (uint)bytes.Length, out var written, null) == 0 || written != bytes.Length)
                throw Failure();
    }

    private static void Close(ref nint handle)
    {
        var owned = handle; handle = 0;
        if (owned != 0) CloseHandle(owned);
    }

    private static InvalidOperationException Failure() => new("Synthetic fixture operation failed.");

    private static void RequireActiveSuite()
    {
        if (Volatile.Read(ref safetyStopped) != 0
            || File.Exists(Path.Combine(Path.GetTempPath(), "process-safety-stop.json")))
            throw new InvalidOperationException("Process scenario safety stop is latched.");
    }

    private static InvalidOperationException StopSuite(string stage)
    {
        Interlocked.Exchange(ref safetyStopped, 1);
        try
        {
            using var stream = new FileStream(Path.Combine(Path.GetTempPath(), "process-safety-stop.json"),
                FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            JsonSerializer.Serialize(stream, new { stage, continuationAllowed = false });
            stream.Flush(true);
        }
        catch (Exception) { /* The in-memory latch remains authoritative for later launches. */ }
        return new InvalidOperationException("Process scenario safety stop is latched.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        internal uint Size;
        internal nint Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        internal ushort Show, ReservedSize;
        internal nint ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct StartupInfoEx { internal StartupInfo Info; internal void* Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { internal nint Process, Thread; internal uint ProcessId, ThreadId; }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int CreatePipe(out nint reader, out nint writer, void* security, uint size);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int SetHandleInformation(nint handle, uint mask, uint flags);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int DuplicateHandle(nint sourceProcess, nint source, nint targetProcess,
        out nint target, uint access, int inherit, uint options);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int GetNamedPipeInfo(nint pipe, uint* flags, out uint outputSize, uint* inputSize, uint* instances);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int WriteFile(nint file, byte* data, uint size, out uint written, void* overlapped);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int PeekNamedPipe(nint pipe, byte* data, uint size, uint* read, out uint available, uint* remaining);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int InitializeProcThreadAttributeList(void* list, uint count, uint flags, ref nuint size);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int UpdateProcThreadAttribute(void* list, uint flags, nuint attribute,
        void* value, nuint size, void* previous, nuint* returned);
    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial void DeleteProcThreadAttributeList(void* list);
    [LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int CreateProcessW(string application, char* command, void* processSecurity,
        void* threadSecurity, int inherit, uint flags, void* environment, string directory,
        ref StartupInfoEx startup, out ProcessInformation information);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint WaitForSingleObject(nint handle, uint milliseconds);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int GetExitCodeProcess(nint process, out uint exitCode);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int TerminateProcess(nint process, uint exitCode);
    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int CloseHandle(nint handle);
}
