// Issue #92 diagnostic controller; compiled by the pinned standalone Framework compiler.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public sealed class NativeAotJob : IDisposable
{
    private SafeFileHandle job;
    private AnonymousPipeServerStream output;
    private AnonymousPipeServerStream error;
    private bool unassignedPending;
    private ManualResetEvent metadataRequest;
    private volatile bool metadataCanceled;
    private Stopwatch metadataClock;
    private long metadataDeadline;
    private MetadataSnapshot metadata;
    public uint? ActiveBeforeStop { get; private set; }
    public bool TerminationRequested { get; private set; }
    public bool TerminationSucceeded { get; private set; }
    public Process Child { get; private set; }
    public StreamReader Output { get; private set; }
    public StreamReader Error { get; private set; }

    public sealed class MemberMetadata
    {
        public int Slot { get; private set; }
        public uint? ProcessId { get; private set; }
        public long? CreationFileTime { get; private set; }
        public string State { get; private set; }
        public string ImageClass { get; private set; }
        public string BasenameClass { get; private set; }
        public string LocationClass { get; private set; }
        public MemberMetadata(int slot, string state, uint? pid, long? created, string image,
            string basename = "unknown", string location = "unknown")
        {
            Slot = slot; State = state; ProcessId = pid; CreationFileTime = created;
            ImageClass = image; BasenameClass = basename; LocationClass = location;
        }
    }

    public sealed class MetadataSnapshot
    {
        public string State { get; private set; }
        public MemberMetadata[] Members { get; private set; }
        public MetadataSnapshot(string state, MemberMetadata[] members)
        { State = state; Members = members; }
    }

    // Prepare the worker before subject execution. Normal drain and termination never join it.
    public void PrepareMetadata()
    {
        if (metadataRequest != null) throw new InvalidOperationException();
        metadataRequest = new ManualResetEvent(false);
        bool retained = false;
        try
        {
            job.DangerousAddRef(ref retained);
            if (!retained || job.IsInvalid) throw new InvalidOperationException();
            IntPtr retainedJob = job.DangerousGetHandle();
            var worker = new Thread(delegate()
            {
                try
                {
                    if (metadataRequest.WaitOne(650000) && !metadataCanceled)
                    {
                        MetadataSnapshot value = CaptureMetadata(retainedJob);
                        if (!MetadataMayContinue)
                            value = new MetadataSnapshot("budget-ended", value.Members);
                        Interlocked.CompareExchange(ref metadata, value, null);
                    }
                }
                catch
                {
                    Interlocked.CompareExchange(ref metadata,
                        new MetadataSnapshot("worker-failed", new MemberMetadata[0]), null);
                }
                finally { job.DangerousRelease(); metadataRequest.Dispose(); }
            });
            worker.IsBackground = true;
            worker.Start();
            retained = false; // The worker now owns this reference.
        }
        finally { if (retained) job.DangerousRelease(); }
    }

    public void RequestMetadata(Stopwatch drainClock, long deadlineMilliseconds)
    {
        if (metadataRequest == null || metadataClock != null) throw new InvalidOperationException();
        metadataClock = drainClock;
        metadataDeadline = deadlineMilliseconds;
        metadataRequest.Set();
    }

    private bool MetadataMayContinue
    { get { return !metadataCanceled && metadataClock != null && metadataClock.ElapsedMilliseconds < metadataDeadline; } }

    public MetadataSnapshot FinishMetadata()
    {
        metadataCanceled = true;
        // Freeze the result without waiting for a slow metadata call or holding its locks.
        MetadataSnapshot absent = new MetadataSnapshot("unavailable-at-stop", new MemberMetadata[0]);
        return Interlocked.CompareExchange(ref metadata, absent, null) ?? absent;
    }

    private MetadataSnapshot CaptureMetadata(IntPtr retainedJob)
    {
        var members = new List<MemberMetadata>();
        int bytes = 8 + 32 * IntPtr.Size;
        IntPtr buffer = Marshal.AllocHGlobal(bytes);
        try
        {
            if (!MetadataMayContinue) return new MetadataSnapshot("budget-ended", members.ToArray());
            long listedBefore = DateTime.UtcNow.ToFileTimeUtc();
            if (!QueryJobProcessList(retainedJob, 3, buffer, (uint)bytes, IntPtr.Zero))
                return new MetadataSnapshot("query-failed", members.ToArray());
            uint assigned = unchecked((uint)Marshal.ReadInt32(buffer));
            uint count = unchecked((uint)Marshal.ReadInt32(buffer, 4));
            if (count > 32 || assigned > 32 || count != assigned)
                return new MetadataSnapshot("invalid-list", members.ToArray());
            var seen = new HashSet<uint>();
            for (int slot = 0; slot < count; slot++)
            {
                if (!MetadataMayContinue) return new MetadataSnapshot("budget-ended", members.ToArray());
                long candidate = Marshal.ReadIntPtr(buffer, 8 + slot * IntPtr.Size).ToInt64();
                if (candidate <= 0 || candidate > uint.MaxValue || !seen.Add((uint)candidate))
                    return new MetadataSnapshot("invalid-list", members.ToArray());
                members.Add(InspectMember(retainedJob, (uint)candidate, slot, listedBefore));
            }
            return new MetadataSnapshot(MetadataMayContinue ? "complete" : "budget-ended", members.ToArray());
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private MemberMetadata InspectMember(IntPtr retainedJob, uint pid, int slot, long listedBefore)
    {
        string state = "open-failed";
        using (var process = new SafeFileHandle(OpenProcess(0x1000, false, pid), true))
        {
            if (process.IsInvalid) return new MemberMetadata(slot, state, null, null, "unknown");
            bool member;
            long created, ignored1, ignored2, ignored3, createdAfter;
            if (!MetadataMayContinue) state = "budget-ended";
            else if (!IsProcessInJob(process, retainedJob, out member) || !member) state = "membership-unverified";
            else if (!MetadataMayContinue) state = "budget-ended";
            else if (!GetProcessTimes(process, out created, out ignored1, out ignored2, out ignored3) ||
                     created <= 0 || created > listedBefore) state = "incarnation-unverified";
            else
            {
                var image = new StringBuilder(32768);
                uint capacity = 32768;
                if (!MetadataMayContinue) state = "budget-ended";
                else if (!QueryFullProcessImageNameW(process, 0, image, ref capacity)) state = "image-unavailable";
                else if (!MetadataMayContinue) state = "budget-ended";
                else if (!GetProcessTimes(process, out createdAfter, out ignored1, out ignored2, out ignored3) ||
                         createdAfter != created) state = "incarnation-unverified";
                else if (!MetadataMayContinue) state = "budget-ended";
                else if (!IsProcessInJob(process, retainedJob, out member) || !member) state = "membership-unverified";
                else if (MetadataMayContinue)
                    return new MemberMetadata(slot, "verified-member", pid, created,
                        ClassifyImage(image.ToString()), ClassifyBasename(image.ToString()),
                        ClassifyLocation(image.ToString()));
                else state = "budget-ended";
            }
        }
        return new MemberMetadata(slot, state, null, null, "unknown");
    }

    private static string ClassifyImage(string image)
    {
        const string vc = @"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\";
        foreach (string name in new[] { "link", "cl", "mspdbsrv", "mspdbcmf", "c1", "c1xx", "c2", "vctip" })
            if (String.Equals(image, vc + name + ".exe", StringComparison.OrdinalIgnoreCase)) return "msvc-" + name;
        if (String.Equals(image, @"C:\Program Files\dotnet\dotnet.exe", StringComparison.OrdinalIgnoreCase)) return "dotnet-host";
        if (String.Equals(image, @"C:\Windows\System32\conhost.exe", StringComparison.OrdinalIgnoreCase)) return "windows-console-host";
        if (String.Equals(image, @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe", StringComparison.OrdinalIgnoreCase)) return "framework-csc";
        if (String.Equals(image, @"C:\Temp\azureauth-native-aot-diagnostics\round-02\packages\runtime.win-x64.microsoft.dotnet.ilcompiler\10.0.12\tools\ilc.exe", StringComparison.OrdinalIgnoreCase)) return "native-aot-ilc";
        return "unknown";
    }

    // Lexical classes only: neither canonical paths nor executable identity/provenance.
    private static string ClassifyBasename(string image)
    {
        int separator = image.LastIndexOf('\\');
        string leaf = image.Substring(separator + 1);
        foreach (string name in new[] { "link", "cl", "mspdbsrv", "mspdbcmf", "c1", "c1xx", "c2",
            "vctip", "dotnet", "conhost", "csc", "ilc" })
            if (String.Equals(leaf, name + ".exe", StringComparison.OrdinalIgnoreCase)) return name;
        return "unknown";
    }

    private static string ClassifyLocation(string image)
    {
        string[] prefixes = {
            @"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\",
            @"C:\Program Files\dotnet\", @"C:\Windows\System32\",
            @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\",
            @"C:\Temp\azureauth-native-aot-diagnostics\round-02\"
        };
        string[] classes = { "msvc-bin-text", "dotnet-installation-text", "system32-text",
            "framework-text", "round-root-text" };
        for (int i = 0; i < prefixes.Length; i++)
            if (image.StartsWith(prefixes[i], StringComparison.OrdinalIgnoreCase)) return classes[i];
        return "unknown";
    }

    public NativeAotJob()
    {
        job = new SafeFileHandle(CreateJobObject(IntPtr.Zero, null), true);
        if (job.IsInvalid) throw new Win32Exception();
        var limits = new ExtendedLimits();
        limits.Basic.LimitFlags = 0x2000 | 0x8; // KILL_ON_JOB_CLOSE | ACTIVE_PROCESS
        limits.Basic.ActiveProcessLimit = 32;
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)))
        {
            job.Dispose();
            throw new Win32Exception();
        }
    }

    public void Start(string executable, string arguments, string working, IDictionary variables)
    {
        output = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        error = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        Output = new StreamReader(output, Encoding.UTF8);
        Error = new StreamReader(error, Encoding.UTF8);
        var environment = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in variables) environment.Add((string)entry.Key, (string)entry.Value);
        var block = new StringBuilder();
        foreach (var entry in environment) block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
        block.Append('\0');
        IntPtr environmentPointer = Marshal.StringToHGlobalUni(block.ToString());
        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
        IntPtr attributes = Marshal.AllocHGlobal(size);
        IntPtr handles = Marshal.AllocHGlobal(IntPtr.Size * 2);
        bool initialized = false;
        var process = new ProcessInformation();
        try
        {
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new Win32Exception();
            initialized = true;
            Marshal.WriteIntPtr(handles, 0, output.ClientSafePipeHandle.DangerousGetHandle());
            Marshal.WriteIntPtr(handles, IntPtr.Size, error.ClientSafePipeHandle.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x20002, handles,
                (IntPtr)(IntPtr.Size * 2), IntPtr.Zero, IntPtr.Zero)) throw new Win32Exception();
            var startup = new StartupInformation();
            startup.Size = Marshal.SizeOf(startup);
            startup.Flags = 0x100; // STARTF_USESTDHANDLES; stdin intentionally unavailable.
            startup.Output = output.ClientSafePipeHandle.DangerousGetHandle();
            startup.Error = error.ClientSafePipeHandle.DangerousGetHandle();
            startup.Attributes = attributes;
            var command = new StringBuilder("\"" + executable + "\" " + arguments);
            // CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
            if (!CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                0x4 | 0x400 | 0x80000 | 0x8000000, environmentPointer, working,
                ref startup, out process)) throw new Win32Exception();
            unassignedPending = true;
            if (!AssignProcessToJobObject(job, process.Process))
            {
                // The root has never executed. This handle identifies its incarnation.
                if (TerminateProcess(process.Process, 1) && WaitForSingleObject(process.Process, 10000) == 0)
                    unassignedPending = false;
                throw new Win32Exception();
            }
            unassignedPending = false;
            Child = Process.GetProcessById((int)process.ProcessId);
            // Framework GetProcessById stores only a PID. Retain its handle before resume.
            if (Child.Handle == IntPtr.Zero) throw new Win32Exception();
            if (ResumeThread(process.Thread) == uint.MaxValue) throw new Win32Exception();
        }
        finally
        {
            if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
            if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
            if (initialized) DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(attributes);
            Marshal.FreeHGlobal(handles);
            Marshal.FreeHGlobal(environmentPointer);
            output.DisposeLocalCopyOfClientHandle();
            error.DisposeLocalCopyOfClientHandle();
        }
    }

    public uint ActiveProcesses
    {
        get
        {
            Accounting info;
            if (!QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero))
                throw new Win32Exception();
            return info.ActiveProcesses;
        }
    }

    public bool Stop()
    {
        metadataCanceled = true;
        if (unassignedPending) return false;
        ActiveBeforeStop = ActiveProcesses;
        if (ActiveBeforeStop == 0) return true;
        TerminationRequested = true;
        TerminationSucceeded = TerminateJobObject(job, 1);
        if (!TerminationSucceeded) throw new Win32Exception();
        var watch = Stopwatch.StartNew();
        while (ActiveProcesses != 0 && watch.ElapsedMilliseconds < 10000) System.Threading.Thread.Sleep(50);
        return ActiveProcesses == 0;
    }

    public void Dispose()
    {
        metadataCanceled = true;
        if (metadataRequest != null)
        {
            try { metadataRequest.Set(); } catch (ObjectDisposedException) { }
        }
        // Closing this noninherited handle also ends owned descendants on controller exit.
        if (job != null) job.Dispose();
        if (Output != null) Output.Dispose();
        if (Error != null) Error.Dispose();
        if (Child != null) Child.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        public long ProcessTime, JobTime;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Accounting
    {
        public long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
        public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInformation
    {
        public int Size;
        public string Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public short ShowWindow, ReservedBytes;
        public IntPtr ReservedPointer, Input, Output, Error, Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, out Accounting info, uint size, IntPtr returned);
    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)]
    private static extern bool QueryJobProcessList(IntPtr job, int kind, IntPtr buffer, uint size, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(SafeFileHandle process, IntPtr job, out bool member);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(SafeFileHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(SafeFileHandle process, uint flags, StringBuilder image, ref uint capacity);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref StartupInformation startup, out ProcessInformation process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
