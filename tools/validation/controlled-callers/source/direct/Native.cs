// Interop layouts and creation-time algorithms adapted from the immutable normal
// WindowsScriptJobLauncher.cs at 56e2b2d24ffe80047109ee52bde3acceb0b6d26f.
#nullable enable
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace ConfidentialWsl;

internal sealed class MemoryPipe : IDisposable
{
    internal SafeFileHandle Reader, Writer;
    private readonly byte[] buffer;
    private readonly Thread pump;
    private int count;
    internal volatile bool Done, Eof, Failed;
    internal DateTimeOffset ReceivedUtc;
    internal ReadOnlyMemory<byte> Bytes => Done && !Failed ? buffer.AsMemory(0, count) : throw new SafeFailure(Fault.Capture);

    internal MemoryPipe(int limit)
    {
        buffer = new byte[limit];
        Native.SecurityAttributes security = Native.InheritableSecurity();
        Native.Check(Native.CreatePipe(out Reader, out Writer, ref security, 4096));
        try
        {
            Native.Check(Native.SetHandleInformation(Reader, 1, 0));
            pump = new Thread(Read) { IsBackground = true };
            pump.Start();
        }
        catch { Reader.Dispose(); Writer.Dispose(); throw; }
    }
    private void Read()
    {
        byte[] chunk = new byte[4096];
        try
        {
            // Only this thread reads the pipe. The supervising thread never joins or
            // performs a blocking pipe read; its existing absolute deadline still applies.
            int calls = 0;
            while (true)
            {
                if (++calls > buffer.Length + 1024) { Failed = true; return; }
                uint wanted = (uint)Math.Min(chunk.Length, buffer.Length - count + 1);
                if (!Native.ReadFile(Reader, chunk, wanted, out uint read, IntPtr.Zero))
                {
                    if (Marshal.GetLastWin32Error() == 109) { Eof = true; ReceivedUtc = DateTimeOffset.UtcNow; return; }
                    Failed = true; return;
                }
                // A successful zero-byte pipe read can reflect a zero-byte write.
                // Only ERROR_BROKEN_PIPE establishes anonymous-pipe EOF here.
                if (read == 0) continue;
                if (read > buffer.Length - count) { Failed = true; return; }
                Buffer.BlockCopy(chunk, 0, buffer, count, (int)read);
                count += (int)read;
            }
        }
        catch { Failed = true; }
        finally { Array.Clear(chunk); Done = true; }
    }
    internal void CloseChildWriter() => Writer.Dispose();
    public void Dispose()
    {
        Writer.Dispose();
        // A marshaled SafeHandle remains held during an outstanding ReadFile. Do not
        // promise that disposal aborts native I/O or synchronously joins its pump.
        Reader.Dispose();
        if (Done) Array.Clear(buffer);
    }
}

internal sealed class InputPipe : IDisposable
{
    internal SafeFileHandle Reader;
    private SafeFileHandle? writer;
    internal InputPipe(bool lifetime)
    {
        Native.SecurityAttributes security = Native.InheritableSecurity();
        if (lifetime)
        {
            Native.Check(Native.CreatePipe(out Reader, out SafeFileHandle ownedWriter, ref security, 0));
            writer = ownedWriter;
            try { Native.Check(Native.SetHandleInformation(writer, 1, 0)); }
            catch { Reader.Dispose(); writer.Dispose(); throw; }
        }
        else
        {
            Reader = Native.CreateFile("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero);
            Native.Check(!Reader.IsInvalid);
        }
    }
    internal void CloseParentRead() => Reader.Dispose();
    internal void CloseWriter() { writer?.Dispose(); writer = null; }
    public void Dispose() { Reader.Dispose(); CloseWriter(); }
}

internal sealed class Child : IDisposable
{
    internal readonly SafeFileHandle Process, Thread;
    internal readonly long CreatedFileTime;
    private bool resumeAttempted;
    internal Child(Native.ProcessInformation info)
    {
        Process = new SafeFileHandle(info.Process, true);
        Thread = new SafeFileHandle(info.Thread, true);
        try { Native.Check(Native.GetProcessTimes(Process, out CreatedFileTime, out _, out _, out _) && CreatedFileTime > 0); }
        catch { Process.Dispose(); Thread.Dispose(); throw; }
    }
    internal void ResumeOnce()
    {
        if (resumeAttempted) throw new SafeFailure(Fault.Native);
        resumeAttempted = true;
        if (Native.ResumeThread(Thread) != 1) throw new SafeFailure(Fault.Native);
        Thread.Dispose();
    }
    internal bool Exited()
    {
        uint wait = Native.WaitForSingleObject(Process, 0);
        if (wait is not (0 or 258)) throw new SafeFailure(Fault.Native);
        return wait == 0;
    }
    internal uint ExitCode() { Native.Check(Exited()); Native.Check(Native.GetExitCodeProcess(Process, out uint code)); return code; }
    public void Dispose() { Thread.Dispose(); Process.Dispose(); }
}

internal static class Native
{
    internal static void Check(bool value) { if (!value) throw new SafeFailure(Fault.Native); }
    internal static SecurityAttributes InheritableSecurity() => new() { Length = Marshal.SizeOf<SecurityAttributes>(), Inherit = true };

    internal static SafeFileHandle NewJob(string publicName, int productCount)
    {
        SafeFileHandle job = CreateJobObject(IntPtr.Zero, publicName);
        int error = Marshal.GetLastWin32Error();
        if (job.IsInvalid || error == 183)
        { job.Dispose(); throw new SafeFailure(Fault.Native); } // Never configure or stop a collided object.
        try
        {
            var limits = new ExtendedLimits();
            limits.Basic.LimitFlags = 0x2008; // KILL_ON_JOB_CLOSE | ACTIVE_PROCESS; no breakaway/UI restrictions.
            limits.Basic.ActiveProcessLimit = (uint)(1 + productCount);
            Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()));
            return job; // Created with no inheritable SECURITY_ATTRIBUTES; sole Job owner is supervisor.
        }
        catch { job.Dispose(); throw; }
    }

    internal static Child StartSuspended(string application, string[] args, string directory,
        InputPipe input, MemoryPipe output, MemoryPipe error, SafeFileHandle? job)
    {
        StringBuilder command = CommandLine(application, args);
        IntPtr size = IntPtr.Zero, attributes = IntPtr.Zero, handles = IntPtr.Zero, jobs = IntPtr.Zero;
        bool initialized = false;
        Child? child = null;
        try
        {
            int count = job is null ? 1 : 2;
            InitializeProcThreadAttributeList(IntPtr.Zero, count, 0, ref size);
            Check(size.ToInt64() is > 0 and <= 65536);
            attributes = Marshal.AllocHGlobal(size);
            Check(InitializeProcThreadAttributeList(attributes, count, 0, ref size)); initialized = true;
            handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handles, 0, input.Reader.DangerousGetHandle());
            Marshal.WriteIntPtr(handles, IntPtr.Size, output.Writer.DangerousGetHandle());
            Marshal.WriteIntPtr(handles, IntPtr.Size * 2, error.Writer.DangerousGetHandle());
            Check(UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x20002, handles, (IntPtr)(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero));
            if (job is not null)
            {
                jobs = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
                Check(UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x2000D, jobs, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero));
            }
            var startup = new StartupInformation { Size = Marshal.SizeOf<StartupInformation>(), Flags = 0x100,
                Input = input.Reader.DangerousGetHandle(), Output = output.Writer.DangerousGetHandle(),
                Error = error.Writer.DangerousGetHandle(), Attributes = attributes };
            // NULL inherits this immediate parent's environment; ordinary direct WSL context is an accepted protocol precondition, not original-shell byte equality.
            // No shell, fabricated home, breakaway, PID reopening or post-creation Job assignment.
            Check(CreateProcess(application, command, IntPtr.Zero, IntPtr.Zero, true, 0x4u | 0x80000u,
                IntPtr.Zero, directory, ref startup, out ProcessInformation info));
            child = new Child(info);
            input.CloseParentRead(); output.CloseChildWriter(); error.CloseChildWriter();
            Check(IsProcessInJob(child.Process, job?.DangerousGetHandle() ?? IntPtr.Zero, out bool member) && member);
            // With job=null, this proves membership in some Job only. The specific Job
            // follows from the contained worker's ordinary child inheritance, not this API.
            return child;
        }
        catch { child?.Dispose(); throw; }
        finally
        {
            // Best effort for this mutable copy only; no general managed-memory erasure claim.
            for (int i = 0; i < command.Length; i++) command[i] = '\0';
            command.Clear();
            if (initialized) DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(jobs); Marshal.FreeHGlobal(handles); Marshal.FreeHGlobal(attributes);
            GC.KeepAlive(job); GC.KeepAlive(input); GC.KeepAlive(output); GC.KeepAlive(error);
        }
    }

    internal static StringBuilder CommandLine(string image, string[] args)
    {
        var command = new StringBuilder();
        Quote(command, image);
        foreach (string arg in args) { command.Append(' '); Quote(command, arg); }
        if (command.Length > 32766) throw new SafeFailure(Fault.Admission);
        return command;
    }
    private static void Quote(StringBuilder result, string value)
    {
        if (value.IndexOf('\0') >= 0) throw new SafeFailure(Fault.Admission);
        result.Append('"'); int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes).Append(c); slashes = 0;
        }
        result.Append('\\', slashes * 2).Append('"');
    }
    internal static Accounting Query(SafeFileHandle job)
    { Check(QueryInformationJobObject(job, 1, out Accounting value, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero)); return value; }

    [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes
    { internal int Length; internal IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] internal bool Inherit; }
    [StructLayout(LayoutKind.Sequential)] internal struct ProcessInformation
    { internal IntPtr Process, Thread; internal uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInformation
    {
        internal int Size; internal string? Reserved, Desktop, Title;
        internal int X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        internal short Show, ReservedSize; internal IntPtr ReservedBytes, Input, Output, Error, Attributes;
    }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    {
        internal long ProcessTime, JobTime; internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSet, MaximumWorkingSet; internal uint ActiveProcessLimit;
        internal UIntPtr Affinity; internal uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    {
        internal BasicLimits Basic;
        internal ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
        internal UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Accounting
    {
        internal long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
        internal uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, out Accounting value, uint size, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(SafeFileHandle process, IntPtr job, out bool member);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInformation startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetProcessTimes(SafeFileHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetExitCodeProcess(SafeFileHandle process, out uint exitCode);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafeFileHandle CreateFile(string path, uint access, uint share, ref SecurityAttributes security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SecurityAttributes security, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool ReadFile(SafeFileHandle file, byte[] buffer, uint size, out uint read, IntPtr overlapped);
}
