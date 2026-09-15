// Windows Slice managed validation controller. This is not product interop.
// Compile only under the accepted protocol using the pinned Framework compiler.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class WindowsValidationJob : IDisposable
{
    private SafeFileHandle job;
    private AnonymousPipeServerStream output;
    private AnonymousPipeServerStream error;
    private bool unassignedPending;
    private readonly bool retainFinalPublishFailures;
    private readonly Stopwatch finalPublishControllerWatch;
    private Stopwatch finalPublishActionWatch;
    private static readonly bool FinalPublishDraftOnly = false;
    private bool finalPublishStartAttempted;
    private bool finalPublishRootCreated;
    private bool finalPublishRootAssigned;
    private bool finalPublishResumeAttempted;
    public bool FinalPublishExecutionMayHaveBegun { get { return finalPublishResumeAttempted; } }
    public bool NeverResumedRootTerminationRequested { get; private set; }
    public bool NeverResumedRootTerminationSucceeded { get; private set; }
    public bool NeverResumedRootExitConfirmed { get; private set; }
    public uint? FinalPublishObservedActive { get; private set; }
    public uint? FinalPublishObservedTotal { get; private set; }
    public uint? ActiveBeforeStop { get; private set; }
    public uint? TotalBeforeStop { get; private set; }
    public uint? TotalAfterStop { get; private set; }
    public uint? ActiveAfterStop { get; private set; }
    public bool TerminationRequested { get; private set; }
    public bool TerminationSucceeded { get; private set; }
    public Process Child { get; private set; }
    public StreamReader Output { get; private set; }
    public StreamReader Error { get; private set; }

    public WindowsValidationJob() : this(false, null) { }

    // PRIVATE DRAFT: a future accepted source/guard binding must remove this gate.
    public static WindowsValidationJob CreateFinalPublishDraft(Stopwatch controllerWatch)
    {
        if (FinalPublishDraftOnly)
            throw new InvalidOperationException("Final publish guard has no accepted execution binding");
        if (controllerWatch == null || !controllerWatch.IsRunning || controllerWatch.ElapsedMilliseconds >= 700000)
            throw new InvalidOperationException("Missing or expired original controller clock");
        return new WindowsValidationJob(true, controllerWatch);
    }

    private WindowsValidationJob(bool retainFailures, Stopwatch controllerWatch)
    {
        retainFinalPublishFailures = retainFailures;
        finalPublishControllerWatch = controllerWatch;
        job = new SafeFileHandle(CreateJobObject(IntPtr.Zero, null), true);
        if (job.IsInvalid) throw new Win32Exception();
        var limits = new ExtendedLimits();
        limits.Basic.LimitFlags = retainFinalPublishFailures ? 0x8u : 0x2008u;
        // Final publish: ACTIVE_PROCESS only. Existing modes retain KILL_ON_JOB_CLOSE.
        // Neither mode permits BREAKAWAY_OK or SILENT_BREAKAWAY_OK.
        limits.Basic.ActiveProcessLimit = 32;
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)))
        {
            job.Dispose();
            throw new Win32Exception();
        }
    }

    // The action watch is the original clock started immediately before this call.
    public void StartFinalPublishDraft(string executable, string arguments, string working,
        IDictionary variables, Stopwatch actionWatch)
    {
        if (FinalPublishDraftOnly || !retainFinalPublishFailures)
            throw new InvalidOperationException("Final publish start has no accepted execution binding");
        if (actionWatch == null || !actionWatch.IsRunning || finalPublishStartAttempted)
            throw new InvalidOperationException("Missing original action clock or repeated start");
        finalPublishActionWatch = actionWatch;
        Start(executable, arguments, working, variables);
    }

    public void Start(string executable, string arguments, string working, IDictionary variables)
    {
        if (retainFinalPublishFailures)
        {
            if (finalPublishStartAttempted)
                throw new InvalidOperationException("Final publish permits one root start only");
            finalPublishStartAttempted = true;
            if (finalPublishActionWatch == null || !finalPublishActionWatch.IsRunning ||
                finalPublishActionWatch.ElapsedMilliseconds >= 600000 ||
                finalPublishControllerWatch.ElapsedMilliseconds >= 700000)
                throw new InvalidOperationException("Missing or expired original deadline");
        }
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
            if (retainFinalPublishFailures) finalPublishRootCreated = true;
            if (!AssignProcessToJobObject(job, process.Process))
            {
                // Final-publish cleanup is centralized in catch, before handle release.
                if (retainFinalPublishFailures) throw new Win32Exception();
                // The root has never executed. This handle identifies its incarnation.
                if (TerminateProcess(process.Process, 1) && WaitForSingleObject(process.Process, 10000) == 0)
                    unassignedPending = false;
                throw new Win32Exception();
            }
            unassignedPending = false;
            if (retainFinalPublishFailures) finalPublishRootAssigned = true;
            Child = Process.GetProcessById((int)process.ProcessId);
            // Framework GetProcessById stores only a PID. Retain its handle before resume.
            if (Child.Handle == IntPtr.Zero) throw new Win32Exception();
            if (retainFinalPublishFailures && (finalPublishActionWatch.ElapsedMilliseconds >= 600000 ||
                finalPublishControllerWatch.ElapsedMilliseconds >= 700000))
                throw new InvalidOperationException("Original deadline expired before resume");
            // Set before the native call: any unknown resume outcome forbids cleanup.
            if (retainFinalPublishFailures) finalPublishResumeAttempted = true;
            if (ResumeThread(process.Thread) == uint.MaxValue) throw new Win32Exception();
        }
        catch
        {
            if (retainFinalPublishFailures && finalPublishRootCreated && !finalPublishResumeAttempted)
            {
                long remaining = 700000 - finalPublishControllerWatch.ElapsedMilliseconds;
                if (remaining > 0 && !NeverResumedRootTerminationRequested)
                {
                    // Original CreateProcess handle, never a PID lookup or descendant stop.
                    NeverResumedRootTerminationRequested = true;
                    NeverResumedRootTerminationSucceeded = TerminateProcess(process.Process, 1);
                    if (NeverResumedRootTerminationSucceeded)
                        NeverResumedRootExitConfirmed = WaitForSingleObject(process.Process,
                            (uint)Math.Min(10000L, Math.Max(0L,
                                700000 - finalPublishControllerWatch.ElapsedMilliseconds))) == 0;
                    if (NeverResumedRootExitConfirmed) unassignedPending = false;
                }
            }
            throw;
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

    private Accounting ReadAccounting()
    {
        Accounting info;
        if (!QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero))
            throw new Win32Exception();
        return info;
    }

    public uint ActiveProcesses { get { return ReadAccounting().ActiveProcesses; } }

    public bool ObserveFinalPublishQuiescence()
    {
        if (!retainFinalPublishFailures)
            throw new InvalidOperationException("Final-publish observation used by another action mode");
        Accounting observed = ReadAccounting();
        FinalPublishObservedActive = observed.ActiveProcesses;
        FinalPublishObservedTotal = observed.TotalProcesses;
        // An unassigned suspended root is not represented by Job accounting.
        return observed.ActiveProcesses == 0 && (!finalPublishRootCreated ||
            finalPublishRootAssigned || NeverResumedRootExitConfirmed);
    }

    public bool Stop()
    {
        if (retainFinalPublishFailures)
            throw new InvalidOperationException("Final publish failures must retain possibly shared work");
        if (unassignedPending) return false;
        Accounting before = ReadAccounting();
        ActiveBeforeStop = before.ActiveProcesses;
        TotalBeforeStop = before.TotalProcesses;
        if (ActiveBeforeStop == 0)
        {
            ActiveAfterStop = 0; TotalAfterStop = before.TotalProcesses;
            return true;
        }
        TerminationRequested = true;
        TerminationSucceeded = TerminateJobObject(job, 1);
        if (!TerminationSucceeded) throw new Win32Exception();
        var watch = Stopwatch.StartNew();
        while (ActiveProcesses != 0 && watch.ElapsedMilliseconds < 10000) System.Threading.Thread.Sleep(50);
        Accounting after = ReadAccounting();
        ActiveAfterStop = after.ActiveProcesses;
        TotalAfterStop = after.TotalProcesses;
        return ActiveAfterStop == 0;
    }

    public void Dispose()
    {
        // Existing modes retain kill-on-close. Final publish closes handles only:
        // no Stop call, no last-handle termination and no implied quiescence.
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
