// Validation launcher; every execution requires a separately admitted exact call.
// This executable is validation infrastructure, not part of the product.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal static class WindowsScriptJobLauncher
{
    // Enabled only for separately admitted validation; compilation grants no execution.
    private static readonly bool ExecutionAdmitted = true;
    private const string Shell = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    private const string ShellHash = "8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e";
    private const int WorkMilliseconds = 330000;
    private const int CleanupMilliseconds = 10000;
    private const int OutputLimit = 16384;
    private static readonly Stopwatch Clock = Stopwatch.StartNew();

    // Arguments: fresh action root, UUID suffix, authority hash, controller hash.
    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted)
        {
            Console.Error.WriteLine("Source-only launcher: execution is not admitted.");
            return 125;
        }
        try { return Run(args); }
        catch (Exception error)
        {
            // Bounded fallback even if creating the local journal failed.
            Console.Error.WriteLine("Launcher failed: {0}; HRESULT={1}",
                error.GetType().Name, error.HResult.ToString(CultureInfo.InvariantCulture));
            return 1;
        }
    }

    private static int Run(string[] args)
    {
        if (args.Length != 4 ||
            !Regex.IsMatch(args[0], @"\AC:\\Temp\\azureauth-windows-slice-108\\named-fixtures-[0-9]{4}\z") ||
            !Regex.IsMatch(args[1], @"\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z") ||
            !IsHash(args[2]) || !IsHash(args[3]))
            throw new ArgumentException("Unbound launcher input");
        string root = args[0];
        string action = root.Substring(root.Length - 4);
        if (int.Parse(action, CultureInfo.InvariantCulture) <= 68)
            throw new ArgumentException("Historical action cannot be reused");
        string jobName = @"Local\azureauth-controller-108-" + action + "-" + args[1];
        string script = Path.Combine(root, "Invoke-WindowsNamedGuardFixtures.ps1");
        AssertDirect(root);

        // The future materializer must supply this fresh, owned, source-bound root.
        // Hold the directory against deletion/rename for the lifetime of this call.
        using (SafeFileHandle directory = OpenDirectory(root))
        using (Journal journal = new Journal(Path.Combine(root, "launcher.jsonl")))
        {
            using (Process self = Process.GetCurrentProcess())
                journal.Write("bootstrap", "pid", self.Id, "creationFileTime",
                    self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture),
                    "session", self.SessionId, "jobName", jobName, "authoritySha256", args[2]);

            SafeFileHandle job = null;
            SafeFileHandle process = null;
            SafeFileHandle thread = null;
            Pipe output = null;
            Pipe error = null;
            string stage = "inputs";
            bool passed = false;
            bool resumed = false;
            int captured = 0;
            Exception failure = null;
            try
            {
                using (FileStream authority = Pin(Path.Combine(root, "authority.json"), args[2], 65536))
                using (FileStream controller = Pin(script, args[3], 65536))
                using (FileStream shell = Pin(Shell, ShellHash, 1048576))
                {
                    stage = "job-create";
                    job = CreateJobObject(IntPtr.Zero, jobName);
                    int creationError = Marshal.GetLastWin32Error();
                    if (job.IsInvalid) throw new Win32Exception(creationError);
                    // An existing object is never configured, terminated, or reused.
                    if (creationError == 183)
                    {
                        job.Dispose();
                        job = null;
                        throw new InvalidOperationException("Job name collision");
                    }
                    var limits = new ExtendedLimits();
                    limits.Basic.LimitFlags = 0x2008; // KILL_ON_JOB_CLOSE | ACTIVE_PROCESS.
                    limits.Basic.ActiveProcessLimit = 32;
                    Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)));
                    // No breakaway flags or UI limits. Child Jobs may nest below this Job.
                    using (SafeFileHandle reopened = OpenJobObject(0xCu, false, jobName))
                        if (reopened.IsInvalid) throw new Win32Exception();
                    journal.Write("job-ready", "queryAndTerminateAccess", true);

                    stage = "capture-create";
                    output = new Pipe(Path.Combine(root, "launcher.stdout.bin"));
                    error = new Pipe(Path.Combine(root, "launcher.stderr.bin"));
                    stage = "process-create";
                    CheckDeadline(root);
                    ProcessInformation child = StartSuspended(job, output, error, root, script, args[2]);
                    process = new SafeFileHandle(child.Process, true);
                    thread = new SafeFileHandle(child.Thread, true);
                    // Close parent copies of the child writers so EOF remains observable.
                    output.CloseWriter();
                    error.CloseWriter();
                    bool inJob;
                    Check(IsProcessInJob(process, job, out inJob));
                    if (!inJob) throw new InvalidOperationException("Creation-time Job assignment absent");
                    long created, exited, kernel, user;
                    Check(GetProcessTimes(process, out created, out exited, out kernel, out user));
                    uint session;
                    Check(ProcessIdToSessionId(child.ProcessId, out session));
                    journal.Write("root-suspended", "pid", child.ProcessId, "creationFileTime",
                        created.ToString(CultureInfo.InvariantCulture), "session", session, "inJob", true);
                    stage = "resume";
                    CheckDeadline(root);
                    // Persist intent before ResumeThread; absence of the next record is ambiguous.
                    journal.Write("resume-requested");
                    uint previousSuspendCount = ResumeThread(thread);
                    if (previousSuspendCount == uint.MaxValue) throw new Win32Exception();
                    resumed = true;
                    if (previousSuspendCount != 1)
                        throw new InvalidOperationException("Unexpected primary-thread suspend count");
                    journal.Write("resumed");
                    thread.Dispose();
                    thread = null;
                    stage = "running";
                    while (true)
                    {
                        CheckDeadline(root);
                        output.Drain(ref captured);
                        error.Drain(ref captured);
                        bool rootExited = HasExited(process);
                        Accounting accounting = Query(job);
                        if (rootExited && accounting.ActiveProcesses == 0 && output.Eof && error.Eof)
                        {
                            uint exitCode;
                            Check(GetExitCodeProcess(process, out exitCode));
                            journal.Write("completed", "rootExited", true, "rootExitCode", exitCode,
                                "activeProcesses", accounting.ActiveProcesses, "totalProcesses", accounting.TotalProcesses,
                                "stdoutEof", output.Eof, "stderrEof", error.Eof, "capturedBytes", captured);
                            passed = exitCode == 0;
                            break;
                        }
                        Thread.Sleep(25);
                    }
                }
            }
            catch (Exception caught) { failure = caught; }
            finally
            {
                // Cleanup precedes fallible failure logging. Creation-time assignment means
                // even a never-resumed root is already owned by this Job.
                if (!passed && job != null && !job.IsInvalid && process != null)
                {
                    bool terminated = TerminateJobObject(job, 1);
                    int terminationError = terminated ? 0 : Marshal.GetLastWin32Error();
                    long deadline = Math.Min(WorkMilliseconds + CleanupMilliseconds,
                        Clock.ElapsedMilliseconds + CleanupMilliseconds);
                    bool rootExited = false;
                    uint? active = null;
                    Exception cleanupFailure = null;
                    bool captureFailed = false;
                    try
                    {
                        do
                        {
                            rootExited = HasExited(process);
                            active = Query(job).ActiveProcesses;
                            if (!captureFailed)
                            {
                                try { output.Drain(ref captured); error.Drain(ref captured); }
                                catch (Exception caught) { captureFailed = true; cleanupFailure = caught; }
                            }
                            // A capture failure must not suppress the remaining lifetime checks.
                            if (rootExited && active == 0 && (captureFailed || (output.Eof && error.Eof))) break;
                            Thread.Sleep(25);
                        } while (Clock.ElapsedMilliseconds < deadline);
                    }
                    catch (Exception caught) { cleanupFailure = caught; }
                    try
                    {
                        journal.Write("cleanup", "terminationRequested", true, "terminationSucceeded", terminated,
                            "terminationError", terminationError, "rootExited", rootExited,
                            "activeProcesses", active, "stdoutEof", output.Eof, "stderrEof", error.Eof,
                            "capturedBytes", captured, "failureType",
                            cleanupFailure == null ? null : cleanupFailure.GetType().Name);
                    }
                    catch (Exception caught) { if (failure == null) failure = caught; }
                }
                // No child inherits this Job handle; the inherited handle allowlist
                // contains stdin/stdout/stderr only. Last-close termination is a fallback,
                // never a substitute for an observed zero count in retained evidence.
                if (thread != null) thread.Dispose();
                if (process != null) process.Dispose();
                if (job != null) job.Dispose();
                if (output != null) output.Dispose();
                if (error != null) error.Dispose();
                if (failure == null && output != null) failure = output.CloseFailure;
                if (failure == null && error != null) failure = error.CloseFailure;
            }
            // Each bounded record is attempted once. A failed journal write must not
            // replace the original failure or suppress the other sampled-status records.
            TryRecord(delegate { RecordCapture(journal, "stdout", output); }, ref failure);
            TryRecord(delegate { RecordCapture(journal, "stderr", error); }, ref failure);
            if (failure != null)
            {
                Exception first = failure;
                TryRecord(delegate { journal.Write("failed", "stage", stage, "resumed", resumed,
                    "failureType", first.GetType().Name, "hresult", first.HResult,
                    "nativeError", first is Win32Exception ? (object)((Win32Exception)first).NativeErrorCode : null); }, ref failure);
            }
            bool success = passed && failure == null;
            TryRecord(delegate { journal.Write("launcher-exit", "passed", success, "capturedBytes", captured); }, ref failure);
            if (failure != null)
                Console.Error.WriteLine("Launcher failed in {0}: {1}; HRESULT={2}", stage,
                    failure.GetType().Name, failure.HResult.ToString(CultureInfo.InvariantCulture));
            return passed && failure == null ? 0 : 1;
        }
    }

    private static void TryRecord(Action record, ref Exception failure)
    {
        try { record(); }
        catch (Exception caught) { if (failure == null) failure = caught; }
    }

    private static void RecordCapture(Journal journal, string stream, Pipe pipe)
    {
        if (pipe == null) { journal.Write("capture", "stream", stream, "initialized", false); return; }
        journal.Write("capture", "stream", stream, "initialized", true,
            "readBytes", pipe.ReadBytes, "confirmedFlushedBytes", pipe.ConfirmedFlushedBytes,
            "eof", pipe.Eof, "overflowDetected", pipe.OverflowDetected,
            "failureStage", pipe.FailureStage, "failureType", pipe.FailureType,
            "failureHresult", pipe.FailureHresult, "failureNativeError", pipe.FailureNativeError,
            "closeFailureType", pipe.CloseFailure == null ? null : pipe.CloseFailure.GetType().Name);
    }

    private static ProcessInformation StartSuspended(SafeFileHandle job, Pipe output, Pipe error,
        string root, string script, string authorityHash)
    {
        var security = new SecurityAttributes();
        security.Length = Marshal.SizeOf(security);
        security.Inherit = true;
        using (SafeFileHandle input = CreateFile("NUL", 0x80000000u, 3, ref security, 3, 0, IntPtr.Zero))
        {
            if (input.IsInvalid) throw new Win32Exception();
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            IntPtr attributes = Marshal.AllocHGlobal(size);
            IntPtr handles = IntPtr.Zero;
            IntPtr jobs = IntPtr.Zero;
            IntPtr environment = IntPtr.Zero;
            bool initialized = false;
            try
            {
                Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size));
                initialized = true;
                handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handles, 0, input.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size, output.Writer.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size * 2, error.Writer.DangerousGetHandle());
                Check(UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x20002, handles,
                    (IntPtr)(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero)); // HANDLE_LIST
                jobs = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
                Check(UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x2000D, jobs,
                    (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero)); // JOB_LIST
                environment = Marshal.StringToHGlobalUni(EnvironmentBlock(root));
                var startup = new StartupInformation();
                startup.Size = Marshal.SizeOf(startup);
                startup.Flags = 0x100; // STARTF_USESTDHANDLES
                startup.Input = input.DangerousGetHandle();
                startup.Output = output.Writer.DangerousGetHandle();
                startup.Error = error.Writer.DangerousGetHandle();
                startup.Attributes = attributes;
                string command = "\"" + Shell + "\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                    script + "\" -Mode Controller -AuthoritySha256 " + authorityHash;
                ProcessInformation child;
                // SUSPENDED | UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | NO_WINDOW.
                Check(CreateProcess(Shell, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true,
                    0x4u | 0x400u | 0x80000u | 0x8000000u, environment, root, ref startup, out child));
                return child;
            }
            finally
            {
                if (initialized) DeleteProcThreadAttributeList(attributes);
                Marshal.FreeHGlobal(environment);
                Marshal.FreeHGlobal(jobs);
                Marshal.FreeHGlobal(handles);
                Marshal.FreeHGlobal(attributes);
                GC.KeepAlive(job);
                GC.KeepAlive(output);
                GC.KeepAlive(error);
            }
        }
    }

    private static string EnvironmentBlock(string root)
    {
        var values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "SystemRoot", @"C:\Windows" }, { "windir", @"C:\Windows" }, { "SystemDrive", "C:" },
            { "TEMP", root }, { "TMP", root }, { "USERPROFILE", root },
            { "PATH", @"C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0" },
            { "PSModulePath", @"C:\Windows\System32\WindowsPowerShell\v1.0\Modules" },
            { "PSModuleAnalysisCachePath", "NUL" }, { "POWERSHELL_TELEMETRY_OPTOUT", "1" },
            { "DOTNET_CLI_TELEMETRY_OPTOUT", "1" }
        };
        var text = new StringBuilder();
        foreach (var value in values) text.Append(value.Key).Append('=').Append(value.Value).Append('\0');
        return text.Append('\0').ToString();
    }

    private static bool IsHash(string value) { return Regex.IsMatch(value, @"\A[0-9a-f]{64}\z"); }
    private static void Check(bool value) { if (!value) throw new Win32Exception(); }
    private static void CheckDeadline(string root)
    {
        if (Clock.ElapsedMilliseconds >= WorkMilliseconds || File.Exists(Path.Combine(root, "cancel")))
            throw new TimeoutException("Launcher deadline or cancellation");
    }
    private static bool HasExited(SafeFileHandle process)
    {
        uint result = WaitForSingleObject(process, 0);
        if (result == uint.MaxValue) throw new Win32Exception();
        if (result != 0 && result != 258) throw new InvalidOperationException("Unexpected process wait result");
        return result == 0;
    }
    private static Accounting Query(SafeFileHandle job)
    {
        Accounting accounting;
        Check(QueryInformationJobObject(job, 1, out accounting, (uint)Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero));
        return accounting;
    }
    private static void AssertDirect(string path)
    {
        for (string current = path; current != null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Reparse path is not admitted");
    }
    private static SafeFileHandle OpenDirectory(string root)
    {
        var security = new SecurityAttributes();
        security.Length = Marshal.SizeOf(security);
        SafeFileHandle handle = CreateFile(root, 0, 3, ref security, 3, 0x02200000u, IntPtr.Zero);
        int code = Marshal.GetLastWin32Error();
        if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(code); }
        return handle;
    }
    private static FileStream Pin(string path, string expected, int maximum)
    {
        AssertDirect(path);
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            if (file.Length > maximum) throw new InvalidOperationException("Input size limit");
            using (SHA256 hash = SHA256.Create())
                if (BitConverter.ToString(hash.ComputeHash(file)).Replace("-", "").ToLowerInvariant() != expected)
                    throw new InvalidOperationException("Input hash mismatch");
            return file;
        }
        catch { file.Dispose(); throw; }
    }

    private sealed class Pipe : IDisposable
    {
        private SafeFileHandle reader;
        public SafeFileHandle Writer;
        private FileStream saved;
        private readonly byte[] buffer = new byte[4096];
        public bool Eof { get; private set; }
        public int ReadBytes { get; private set; }
        public int ConfirmedFlushedBytes { get; private set; }
        public bool OverflowDetected { get; private set; }
        public string FailureStage { get; private set; }
        public string FailureType { get; private set; }
        public int? FailureHresult { get; private set; }
        public int? FailureNativeError { get; private set; }
        public Exception CloseFailure { get; private set; }
        public Pipe(string path)
        {
            try
            {
                saved = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                var security = new SecurityAttributes();
                security.Length = Marshal.SizeOf(security);
                security.Inherit = true;
                Check(CreatePipe(out reader, out Writer, ref security, 0));
                Check(SetHandleInformation(reader, 1, 0));
            }
            catch { Dispose(); throw; }
        }
        public void CloseWriter() { Writer.Dispose(); }
        public void Drain(ref int captured)
        {
            if (Eof) return;
            if (FailureStage != null) throw new InvalidOperationException("Capture previously failed");
            string stage = "pipe-peek";
            try
            {
                uint available;
                // This thread exclusively owns all I/O on this read handle.
                if (!PeekNamedPipe(reader, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero))
                {
                    int code = Marshal.GetLastWin32Error();
                    if (code == 109) { Eof = true; return; }
                    throw new Win32Exception(code);
                }
                if (available == 0) return;
                stage = "output-limit";
                if (captured >= OutputLimit)
                {
                    OverflowDetected = true;
                    throw new InvalidOperationException("Combined console output limit");
                }
                uint requested = Math.Min(available, (uint)Math.Min(buffer.Length, OutputLimit - captured));
                uint read;
                stage = "pipe-read";
                Check(ReadFile(reader, buffer, requested, out read, IntPtr.Zero));
                if (read == 0) throw new InvalidOperationException("Unexpected empty pipe read");
                ReadBytes += checked((int)read);
                captured += checked((int)read);
                stage = "file-write";
                saved.Write(buffer, 0, checked((int)read));
                stage = "file-flush";
                saved.Flush(true);
                // On failure the file may have an unknown partial tail. This is only
                // the byte count covered by completed writes AND successful flushes.
                ConfirmedFlushedBytes = ReadBytes;
            }
            catch (Exception caught)
            {
                // Preserve the first capture failure across subsequent cleanup attempts.
                LatchFailure(stage, caught);
                throw;
            }
        }
        private void LatchFailure(string stage, Exception caught)
        {
            if (FailureStage != null) return;
            FailureStage = stage;
            FailureType = caught.GetType().Name;
            FailureHresult = caught.HResult;
            if (caught is Win32Exception) FailureNativeError = ((Win32Exception)caught).NativeErrorCode;
        }
        private void CloseResource(IDisposable resource, string stage)
        {
            if (resource == null) return;
            try { resource.Dispose(); }
            catch (Exception caught)
            {
                if (CloseFailure == null) CloseFailure = caught;
                LatchFailure(stage, caught);
            }
        }
        public void Dispose()
        {
            // Failure of one close cannot suppress the other closes or later metadata.
            CloseResource(Writer, "writer-close");
            CloseResource(reader, "reader-close");
            CloseResource(saved, "file-close");
        }
    }

    private sealed class Journal : IDisposable
    {
        private readonly FileStream file;
        public Journal(string path) { file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read); }
        public void Write(string kind, params object[] fields)
        {
            var text = new StringBuilder("{\"event\":").Append(Json(kind));
            text.Append(",\"elapsedMilliseconds\":").Append(Clock.ElapsedMilliseconds.ToString(CultureInfo.InvariantCulture));
            for (int index = 0; index < fields.Length; index += 2)
                text.Append(',').Append(Json((string)fields[index])).Append(':').Append(Json(fields[index + 1]));
            byte[] bytes = Encoding.UTF8.GetBytes(text.Append("}\n").ToString());
            if (file.Length + bytes.Length > 16384) throw new InvalidOperationException("Journal size limit");
            file.Write(bytes, 0, bytes.Length);
            file.Flush(true);
        }
        private static string Json(object value)
        {
            if (value == null) return "null";
            if (value is bool) return (bool)value ? "true" : "false";
            if (!(value is string)) return Convert.ToString(value, CultureInfo.InvariantCulture);
            var text = new StringBuilder("\"");
            foreach (char item in (string)value)
            {
                if (item == '\\' || item == '"') text.Append('\\').Append(item);
                else if (item < 32) text.Append("\\u").Append(((int)item).ToString("x4", CultureInfo.InvariantCulture));
                else text.Append(item);
            }
            return text.Append('"').ToString();
        }
        public void Dispose() { file.Dispose(); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes
    { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation
    { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInformation
    {
        public int Size; public string Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        public short Show, ReservedSize; public IntPtr ReservedBytes, Input, Output, Error, Attributes;
    }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    {
        public long ProcessTime, JobTime; public uint LimitFlags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    {
        public BasicLimits Basic;
        public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Accounting
    {
        public long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
        public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle OpenJobObject(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, out Accounting accounting, uint size, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(SafeFileHandle process, SafeFileHandle job, out bool inJob);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory,
        ref StartupInformation startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(SafeFileHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint session);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(SafeFileHandle process, out uint exitCode);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, ref SecurityAttributes security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SecurityAttributes security, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool PeekNamedPipe(SafeFileHandle pipe, IntPtr buffer, uint size, IntPtr read, out uint available, IntPtr left);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(SafeFileHandle file, byte[] buffer, uint size, out uint read, IntPtr overlapped);
}
