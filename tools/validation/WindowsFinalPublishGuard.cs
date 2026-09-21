// Windows Slice managed validation controller. This is not product interop.
// Compile only under the accepted protocol using the pinned Framework compiler.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

public sealed class WindowsValidationJob : IDisposable
{
    private SafeFileHandle job;
    private AnonymousPipeServerStream output;
    private AnonymousPipeServerStream error;
    private bool unassignedPending;
    private readonly bool retainFinalPublishFailures;
    private readonly Stopwatch finalPublishControllerWatch;
    private readonly long finalPublishOuterDeadlineCounter;
    private Stopwatch finalPublishActionWatch;
    private Action finalPublishBeforeResume;
    private readonly List<SafeFileHandle> auditProcessHandles = new List<SafeFileHandle>();
    private static readonly bool FinalPublishDraftOnly = false;
    private bool finalPublishStartAttempted;
    private bool finalPublishRootCreated;
    private bool finalPublishRootAssigned;
    private bool finalPublishResumeAttempted;
    private bool finalPublishAuditAttempted;
    private static bool namedRecoveryAttempted;
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
    public string JobName { get; private set; }
    public int JobSessionId { get; private set; }
    public bool NamedJobRightsVerified { get; private set; }
    public string RootCreationFileTime { get; private set; }

    public WindowsValidationJob() : this(false, null, 0,
        "Local\\azureauth-validation-108-" + Guid.NewGuid().ToString("N")) { }

    // PRIVATE DRAFT: a future accepted source/guard binding must remove this gate.
    public static WindowsValidationJob CreateFinalPublishDraft(Stopwatch controllerWatch,
        long outerDeadlineCounter, string jobName)
    {
        if (FinalPublishDraftOnly)
            throw new InvalidOperationException("Final publish guard has no accepted execution binding");
        if (controllerWatch == null || !controllerWatch.IsRunning || controllerWatch.ElapsedMilliseconds >= 1900000)
            throw new InvalidOperationException("Missing or expired original controller clock");
        if (!Stopwatch.IsHighResolution || Stopwatch.Frequency <= 0 ||
            outerDeadlineCounter <= 0 || outerDeadlineCounter <= Stopwatch.GetTimestamp())
            throw new InvalidOperationException("Missing or expired original shared counter deadline");
        AssertFinalJobName(jobName);
        return new WindowsValidationJob(true, controllerWatch, outerDeadlineCounter, jobName);
    }

    private WindowsValidationJob(bool retainFailures, Stopwatch controllerWatch,
        long outerDeadlineCounter, string jobName)
    {
        retainFinalPublishFailures = retainFailures;
        finalPublishControllerWatch = controllerWatch;
        finalPublishOuterDeadlineCounter = outerDeadlineCounter;
        if (retainFinalPublishFailures) AssertFinalPublishTime(false);
        JobName = jobName;
        using (Process current = Process.GetCurrentProcess()) JobSessionId = current.SessionId;
        IntPtr created = CreateJobObject(IntPtr.Zero, JobName);
        int creationError = Marshal.GetLastWin32Error();
        job = new SafeFileHandle(created, true);
        if (job.IsInvalid) throw new Win32Exception(creationError);
        // CreateJobObject can open an existing object. Never configure that object.
        if (creationError == 183)
        {
            job.Dispose();
            throw new InvalidOperationException("Final Job name already exists");
        }
        if (retainFinalPublishFailures && FinalPublishRemainingMilliseconds(false) <= 0)
        {
            job.Dispose();
            throw new InvalidOperationException("Original deadline expired before named reopen");
        }
        IntPtr reopenedValue = OpenJobObject(0xCu, false, JobName);
        int reopenError = Marshal.GetLastWin32Error();
        using (var reopened = new SafeFileHandle(reopenedValue, true))
        {
            if (reopened.IsInvalid)
            {
                job.Dispose();
                throw new Win32Exception(reopenError);
            }
            // Verify QUERY and TERMINATE access without exercising termination.
            NamedJobRightsVerified = true;
        }
        if (retainFinalPublishFailures && FinalPublishRemainingMilliseconds(false) <= 0)
        {
            job.Dispose();
            throw new InvalidOperationException("Original deadline expired after Job creation");
        }
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
        if (retainFinalPublishFailures && FinalPublishRemainingMilliseconds(false) <= 0)
        {
            job.Dispose();
            throw new InvalidOperationException("Original deadline expired after Job configuration");
        }
    }

    // The earlier shared QPC deadline never restarts at receipt or guard creation.
    // Floor remaining milliseconds so no wait can round beyond that deadline.
    private long FinalPublishRemainingMilliseconds(bool requireAction)
    {
        if (!retainFinalPublishFailures || finalPublishControllerWatch == null ||
            !finalPublishControllerWatch.IsRunning) return 0;
        long ticks = finalPublishOuterDeadlineCounter - Stopwatch.GetTimestamp();
        if (ticks <= 0) return 0;
        long shared = (long)Math.Floor(Math.Min(1900000m,
            (decimal)ticks * 1000m / Stopwatch.Frequency));
        long remaining = Math.Min(shared, 1900000 - finalPublishControllerWatch.ElapsedMilliseconds);
        if (requireAction)
        {
            if (finalPublishActionWatch == null || !finalPublishActionWatch.IsRunning) return 0;
            remaining = Math.Min(remaining, 1800000 - finalPublishActionWatch.ElapsedMilliseconds);
        }
        return Math.Max(0L, remaining);
    }

    private void AssertFinalPublishTime(bool requireAction)
    {
        if (FinalPublishRemainingMilliseconds(requireAction) <= 0)
            throw new InvalidOperationException("Missing or expired original shared/controller/action deadline");
    }

    // The action watch is the original clock started immediately before this call.
    public void StartFinalPublishDraft(string executable, string arguments, string working,
        IDictionary variables, Stopwatch actionWatch, Action beforeResume)
    {
        if (FinalPublishDraftOnly || !retainFinalPublishFailures)
            throw new InvalidOperationException("Final publish start has no accepted execution binding");
        if (actionWatch == null || !actionWatch.IsRunning || finalPublishStartAttempted || beforeResume == null)
            throw new InvalidOperationException("Missing original action clock or repeated start");
        finalPublishActionWatch = actionWatch;
        finalPublishBeforeResume = beforeResume;
        Start(executable, arguments, working, variables);
    }

    public void Start(string executable, string arguments, string working, IDictionary variables)
    {
        if (retainFinalPublishFailures)
        {
            if (finalPublishStartAttempted)
                throw new InvalidOperationException("Final publish permits one root start only");
            finalPublishStartAttempted = true;
            AssertFinalPublishTime(true);
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
            if (retainFinalPublishFailures) AssertFinalPublishTime(true);
            // CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
            if (!CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                0x4 | 0x400 | 0x80000 | 0x8000000, environmentPointer, working,
                ref startup, out process)) throw new Win32Exception();
            unassignedPending = true;
            if (retainFinalPublishFailures) finalPublishRootCreated = true;
            if (retainFinalPublishFailures) AssertFinalPublishTime(true);
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
            if (retainFinalPublishFailures) AssertFinalPublishTime(true);
            Child = Process.GetProcessById((int)process.ProcessId);
            // Framework GetProcessById stores only a PID. Retain its handle before resume.
            if (Child.Handle == IntPtr.Zero) throw new Win32Exception();
            if (retainFinalPublishFailures)
            {
                long creation, exited, kernel, user;
                bool member;
                AssertFinalPublishTime(true);
                if (!GetProcessTimes(process.Process, out creation, out exited, out kernel, out user) || creation <= 0)
                    throw new InvalidOperationException("Suspended root creation time is unestablished");
                AssertFinalPublishTime(true);
                if (!IsProcessInJob(process.Process, job, out member) || !member)
                    throw new InvalidOperationException("Suspended root identity is unestablished");
                RootCreationFileTime = creation.ToString(CultureInfo.InvariantCulture);
                AssertFinalPublishTime(true);
                // The exact caller must persist its binding and check cancellation
                // synchronously. A failure remains in the never-resumed stop path.
                finalPublishBeforeResume();
            }
            if (retainFinalPublishFailures) AssertFinalPublishTime(true);
            // Set before the native call: any unknown resume outcome forbids cleanup.
            if (retainFinalPublishFailures) finalPublishResumeAttempted = true;
            if (ResumeThread(process.Thread) == uint.MaxValue) throw new Win32Exception();
            if (retainFinalPublishFailures) AssertFinalPublishTime(true);
        }
        catch
        {
            if (retainFinalPublishFailures && finalPublishRootCreated && !finalPublishResumeAttempted)
            {
                long stopBeganCounter = Stopwatch.GetTimestamp();
                long remaining = FinalPublishRemainingMilliseconds(true);
                if (remaining > 0 && !NeverResumedRootTerminationRequested)
                {
                    // Original CreateProcess handle, never a PID lookup or descendant stop.
                    NeverResumedRootTerminationRequested = true;
                    NeverResumedRootTerminationSucceeded = TerminateProcess(process.Process, 1);
                    if (NeverResumedRootTerminationSucceeded)
                    {
                        // A delayed native return cannot grant a new wait or extend
                        // the existing ten-second stop window or either original clock.
                        decimal elapsed = (decimal)(Stopwatch.GetTimestamp() - stopBeganCounter) *
                            1000m / Stopwatch.Frequency;
                        long stopRemaining = (long)Math.Floor(Math.Max(0m, 10000m - elapsed));
                        long wait = Math.Min(stopRemaining, FinalPublishRemainingMilliseconds(true));
                        if (wait > 0)
                        {
                            uint observed = WaitForSingleObject(process.Process, (uint)wait);
                            decimal observedElapsed = (decimal)(Stopwatch.GetTimestamp() - stopBeganCounter) *
                                1000m / Stopwatch.Frequency;
                            NeverResumedRootExitConfirmed = observed == 0 && observedElapsed < 10000m &&
                                FinalPublishRemainingMilliseconds(true) > 0;
                        }
                    }
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
        AssertFinalPublishTime(false);
        Accounting observed = ReadAccounting();
        FinalPublishObservedActive = observed.ActiveProcesses;
        FinalPublishObservedTotal = observed.TotalProcesses;
        // An unassigned suspended root is not represented by Job accounting.
        return observed.ActiveProcesses == 0 && (!finalPublishRootCreated ||
            finalPublishRootAssigned || NeverResumedRootExitConfirmed);
    }

    // One bounded, non-atomic observation of this retained Job only. Successful
    // process handles stay held until the caller persists the audit and disposes us.
    public IDictionary ObserveFinalPublishMembers()
    {
        if (!retainFinalPublishFailures || finalPublishAuditAttempted)
            throw new InvalidOperationException("Final audit used by another mode or repeated");
        finalPublishAuditAttempted = true;
        return ObserveMembers(job, JobName, JobSessionId,
            () => FinalPublishRemainingMilliseconds(false) > 0, auditProcessHandles);
    }

    private static void AssertFinalJobName(string name)
    {
        if (name == null || !Regex.IsMatch(name,
            @"\ALocal\\azureauth-final-publish-108-(?!0000)[0-9]{4}-[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z"))
            throw new InvalidOperationException("Missing exact final Job name");
    }

    // A separately admitted observer may open one exact same-session name once.
    // The persistence callback runs before any observed process or Job handle closes.
    public static IDictionary ObserveNamedFinalPublish(string name, int expectedSession,
        Stopwatch originalWatch, long originalDeadlineCounter, Action<IDictionary> persist)
    {
        if (namedRecoveryAttempted || originalWatch == null || !originalWatch.IsRunning ||
            !Stopwatch.IsHighResolution || Stopwatch.Frequency <= 0 || persist == null)
            throw new InvalidOperationException("Missing original observation clock or repeated recovery");
        namedRecoveryAttempted = true;
        AssertFinalJobName(name);
        Func<bool> hasTime = () => originalWatch.ElapsedMilliseconds < 30000 &&
            originalDeadlineCounter > Stopwatch.GetTimestamp();
        int session;
        using (Process current = Process.GetCurrentProcess()) session = current.SessionId;
        var result = new Hashtable {
            { "jobName", name }, { "expectedSessionId", expectedSession }, { "sessionId", session },
            { "status", "not-opened" }, { "openError", null }, { "audit", null }
        };
        var retained = new List<SafeFileHandle>();
        SafeFileHandle opened = null;
        try
        {
            if (expectedSession < 0 || session != expectedSession) result["status"] = "session-mismatch";
            else if (!hasTime()) result["status"] = "deadline";
            else
            {
                IntPtr handle = OpenJobObject(0x4u, false, name);
                int errorCode = Marshal.GetLastWin32Error();
                opened = new SafeFileHandle(handle, true);
                if (opened.IsInvalid)
                {
                    result["openError"] = errorCode;
                    result["status"] = errorCode == 2 ? "not-found" :
                        errorCode == 5 ? "access-denied" : "open-failed";
                }
                else
                {
                    result["status"] = "opened-query-only";
                    result["audit"] = ObserveMembers(opened, name, session, hasTime, retained);
                }
            }
            if (!hasTime()) result["status"] = "deadline";
            persist(result);
        }
        finally
        {
            foreach (SafeFileHandle handle in retained) handle.Dispose();
            if (opened != null) opened.Dispose();
        }
        // Persistence and handle closure are part of the original observation,
        // not a fresh allowance following the native query pass.
        if (!hasTime())
            throw new InvalidOperationException("Named Job observation exceeded its original deadline");
        return result;
    }

    private static IDictionary ObserveMembers(SafeFileHandle observedJob, string name, int session,
        Func<bool> outerHasTime, List<SafeFileHandle> retained)
    {
        var watch = Stopwatch.StartNew();
        Func<bool> hasTime = () => watch.ElapsedMilliseconds < 5000 && outerHasTime();
        var members = new ArrayList();
        var result = new Hashtable {
            { "complete", false }, { "querySucceeded", false }, { "atomic", false },
            { "jobName", name }, { "sessionId", session },
            { "assigned", null }, { "returned", null }, { "queryError", null },
            { "members", members }, { "startedCounter", Stopwatch.GetTimestamp().ToString(CultureInfo.InvariantCulture) }
        };
        IntPtr buffer = Marshal.AllocHGlobal(8 + 32 * IntPtr.Size);
        try
        {
            if (!hasTime())
                return result;
            uint written;
            bool queried = QueryInformationJobObject(observedJob, 3, buffer, (uint)(8 + 32 * IntPtr.Size), out written);
            int queryError = Marshal.GetLastWin32Error();
            if (!queried) { result["queryError"] = queryError; return result; }
            result["querySucceeded"] = true;
            uint assigned = unchecked((uint)Marshal.ReadInt32(buffer, 0));
            uint returned = unchecked((uint)Marshal.ReadInt32(buffer, 4));
            result["assigned"] = assigned; result["returned"] = returned;
            if (assigned > 32 || returned > 32 || returned != assigned ||
                written < 8 + returned * IntPtr.Size || written > 8 + 32 * IntPtr.Size)
                return result;
            bool complete = true;
            var seen = new HashSet<uint>();
            for (int index = 0; index < returned; index++)
            {
                if (!hasTime())
                    return result;
                ulong rawPid = unchecked((ulong)Marshal.ReadIntPtr(buffer, 8 + index * IntPtr.Size).ToInt64());
                if (rawPid == 0 || rawPid > uint.MaxValue) return result;
                uint pid = (uint)rawPid;
                if (!seen.Add(pid)) return result;
                var member = new Hashtable {
                    { "pid", pid }, { "creationFileTime", null }, { "inJob", null },
                    { "imageName", null }, { "status", "open-failed" }, { "win32Error", null }
                };
                members.Add(member);
                if (!hasTime()) { member["status"] = "deadline"; return result; }
                IntPtr opened = OpenProcess(0x1000u, false, pid);
                int openError = Marshal.GetLastWin32Error();
                var handle = new SafeFileHandle(opened, true);
                if (handle.IsInvalid)
                {
                    handle.Dispose(); member["win32Error"] = openError; complete = false; continue;
                }
                retained.Add(handle);
                long creation, exited, kernel, user;
                bool inJob;
                if (!hasTime()) { member["status"] = "deadline"; return result; }
                if (!GetProcessTimes(handle.DangerousGetHandle(), out creation, out exited, out kernel, out user))
                {
                    member["win32Error"] = Marshal.GetLastWin32Error(); member["status"] = "time-failed";
                    complete = false; continue;
                }
                if (creation <= 0) { member["status"] = "invalid-time"; complete = false; continue; }
                member["creationFileTime"] = creation.ToString(CultureInfo.InvariantCulture);
                if (!hasTime()) { member["status"] = "deadline"; return result; }
                if (!IsProcessInJob(handle.DangerousGetHandle(), observedJob, out inJob))
                {
                    member["win32Error"] = Marshal.GetLastWin32Error(); member["status"] = "membership-failed";
                    complete = false; continue;
                }
                member["inJob"] = inJob;
                if (!inJob) { member["status"] = "not-member"; complete = false; continue; }
                var image = new StringBuilder(32768);
                uint capacity = 32768;
                if (!hasTime()) { member["status"] = "deadline"; return result; }
                if (!QueryFullProcessImageName(handle, 0, image, ref capacity))
                {
                    member["win32Error"] = Marshal.GetLastWin32Error(); member["status"] = "image-failed";
                    complete = false; continue;
                }
                string basename = Path.GetFileName(image.ToString());
                if (basename.Length == 0 || basename.Length > 260)
                { member["status"] = "image-limit"; complete = false; continue; }
                member["imageName"] = basename; member["status"] = "observed-member";
            }
            result["complete"] = complete && hasTime();
            return result;
        }
        finally
        {
            result["endedCounter"] = Stopwatch.GetTimestamp().ToString(CultureInfo.InvariantCulture);
            result["elapsedMilliseconds"] = watch.ElapsedMilliseconds;
            Marshal.FreeHGlobal(buffer);
        }
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
        foreach (SafeFileHandle handle in auditProcessHandles) handle.Dispose();
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
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(IntPtr process, SafeFileHandle job, out bool result);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(SafeFileHandle process, uint flags, StringBuilder image, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, out Accounting info, uint size, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, IntPtr info, uint size, out uint returned);
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
