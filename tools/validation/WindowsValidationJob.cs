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
    public uint? ActiveBeforeStop { get; private set; }
    public uint? TotalBeforeStop { get; private set; }
    public uint? TotalAfterStop { get; private set; }
    public uint? ActiveAfterStop { get; private set; }
    public bool TerminationRequested { get; private set; }
    public bool TerminationSucceeded { get; private set; }
    public Process Child { get; private set; }
    public StreamReader Output { get; private set; }
    public StreamReader Error { get; private set; }

    public WindowsValidationJob()
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

    private Accounting ReadAccounting()
    {
        Accounting info;
        if (!QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero))
            throw new Win32Exception();
        return info;
    }

    public uint ActiveProcesses { get { return ReadAccounting().ActiveProcesses; } }

    public bool Stop()
    {
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
        // Closing the noninherited Job handle ends all assigned owned descendants.
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
