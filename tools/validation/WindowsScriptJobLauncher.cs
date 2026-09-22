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
    private const int PublicationWorkMilliseconds = 2000000;
    private const int PublicationTotalMilliseconds = 2010000;
    private const int PublicationAuditMilliseconds = 5000;
    private const int PublicationFinalRecordReserveMilliseconds = 1000;
    private static readonly Stopwatch Clock = Stopwatch.StartNew();

    // Fixture: four args. Publication: seven; its fixed fixture adds a case selector.
    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted)
        {
            Console.Error.WriteLine("Source-only launcher: execution is not admitted.");
            return 125;
        }
        try
        {
            return args.Length > 0 && (args[0] == "--publication" || args[0] == "--publication-fixture")
                ? RunPublication(args) : Run(args);
        }
        catch (Exception error)
        {
            // Publication owns its deadline-aware diagnostics; never bypass its cutoff.
            if (args.Length > 0 && (args[0] == "--publication" || args[0] == "--publication-fixture")) return 1;
            // Bounded fallback even if creating the local journal failed.
            Console.Error.WriteLine("Launcher failed: {0}; HRESULT={1}",
                error.GetType().Name, error.HResult.ToString(CultureInfo.InvariantCulture));
            return 1;
        }
    }

    // After a resume attempt, observe without termination or future name-recovery promises.
    private static int RunPublication(string[] args)
    {
        string fixture = null;
        if (args.Length > 0 && args[0] == "--publication-fixture")
        {
            if (args.Length != 8 || (args[1] != "normal" && args[1] != "pre-resume" &&
                args[1] != "resume-unknown" && args[1] != "timeout" && args[1] != "overflow" &&
                args[1] != "journal-cancel"))
                throw new ArgumentException("Unbound publication fixture case");
            fixture = args[1];
            var bound = new string[7];
            bound[0] = "--publication";
            Array.Copy(args, 2, bound, 1, 6);
            args = bound;
        }
        string rootPattern = fixture == null
            ? @"\AC:\\Temp\\azureauth-windows-slice-108\\actions\\[0-9]{4}\z"
            : @"\AC:\\Temp\\azureauth-windows-slice-108\\publication-fixtures-[0-9]{4}\z";
        if (args.Length != 7 || args[0] != "--publication" ||
            !Regex.IsMatch(args[1], rootPattern) ||
            !Regex.IsMatch(args[2], @"\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z") ||
            !IsHash(args[3]) || !IsHash(args[4]) || !IsHash(args[5]) || !IsHash(args[6]))
            throw new ArgumentException("Unbound publication launcher input");
        string root = args[1];
        // Admitted fixture argv bind a fixed payload and fixed clocks.
        int workMilliseconds = fixture == null ? PublicationWorkMilliseconds : 12000;
        int totalMilliseconds = fixture == null ? PublicationTotalMilliseconds : 22000;
        string action = root.Substring(root.Length - 4);
        if (int.Parse(action, CultureInfo.InvariantCulture) <= 84)
            throw new ArgumentException("Historical publication action cannot be reused");
        string jobName = @"Local\azureauth-publication-108-" + action + "-" + args[2];
        string controllerDirectory = Path.Combine(root, "controller");
        string script = Path.Combine(controllerDirectory, "Start-WindowsFinalPublish.draft.ps1");
        AssertDirect(root);
        AssertDirect(controllerDirectory);
        SafeFileHandle directory = null, scripts = null;
        Journal journal = null;
        Exception failure = null;
        long finalDeadline = totalMilliseconds;
        bool completionReady = false;
        try
        {
            directory = OpenDirectory(root);
            scripts = OpenDirectory(controllerDirectory);
            journal = new Journal(Path.Combine(root, "launcher.jsonl"), 65536);
            SafeFileHandle job = null;
            SafeFileHandle process = null;
            SafeFileHandle thread = null;
            var inputs = new List<IDisposable>();
            var memberHandles = new List<SafeFileHandle>();
            Pipe output = null;
            Pipe error = null;
            string stage = "inputs";
            bool rootCreated = false;
            bool resumeAttempted = false;
            bool resumed = false;
            bool completed = false;
            bool evidenceIncomplete = false;
            bool neverResumedTerminationRequested = false;
            bool neverResumedTerminationSucceeded = false;
            int? neverResumedTerminationError = null;
            int captured = 0;
            int session = -1;
            var lifetime = new PublicationLifetime();
            var audit = new PublicationAudit();
            try
            {
                using (Process self = Process.GetCurrentProcess())
                {
                    session = self.SessionId;
                    journal.Write("publication-bootstrap", "pid", self.Id, "creationFileTime",
                        self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture),
                        "session", session, "action", action, "jobName", jobName,
                        "fixtureCase", fixture,
                        "authoritySha256", args[3], "bootstrapSha256", args[4],
                        "reservationSha256", args[5], "invocationSha256", args[6],
                        "workDeadlineMilliseconds", workMilliseconds,
                        "totalDeadlineMilliseconds", totalMilliseconds);
                }
                CheckPublicationDeadline(root, workMilliseconds);
                inputs.Add(Pin(Path.Combine(root, "authority.json"), args[3], 8388608));
                inputs.Add(Pin(script, args[4], 65536));
                inputs.Add(Pin(Path.Combine(root, "started.json"), args[5], 8388608));
                inputs.Add(Pin(Path.Combine(root, "invocation.json"), args[6], 8388608));
                inputs.Add(Pin(Shell, ShellHash, 1048576));
                CheckPublicationDeadline(root, workMilliseconds);
                stage = "job-create";
                job = CreateJobObject(IntPtr.Zero, jobName);
                int creationError = Marshal.GetLastWin32Error();
                if (job.IsInvalid) throw new Win32Exception(creationError);
                if (creationError == 183)
                {
                    job.Dispose();
                    job = null;
                    throw new InvalidOperationException("Publication Job name collision");
                }
                var limits = new ExtendedLimits();
                limits.Basic.LimitFlags = 0x8; // ACTIVE_PROCESS only; never KILL_ON_JOB_CLOSE.
                limits.Basic.ActiveProcessLimit = 32;
                Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)));
                // No breakaway, no inherited Job handle, and no assignment of this owner.
                using (SafeFileHandle reopened = OpenJobObject(0x4u, false, jobName))
                    if (reopened.IsInvalid) throw new Win32Exception();
                using (Process self = Process.GetCurrentProcess())
                {
                    bool ownerInJob;
                    Check(IsProcessInJob(self.Handle, job, out ownerInJob));
                    if (ownerInJob) throw new InvalidOperationException("Publication owner entered its Job");
                }
                journal.Write("publication-job-ready", "queryAccess", true, "ownerOutsideJob", true,
                    "activeProcessLimit", 32, "killOnClose", false, "breakaway", false);
                stage = "capture-create";
                output = new Pipe(Path.Combine(root, "launcher.stdout.bin"));
                error = new Pipe(Path.Combine(root, "launcher.stderr.bin"));
                stage = "process-create";
                CheckPublicationDeadline(root, workMilliseconds);
                string arguments = "-ActionName " + action + " -ReservationSha256 " + args[5] +
                    " -InvocationSha256 " + args[6] + " -AuthoritySha256 " + args[3];
                ProcessInformation child = StartSuspended(job, output, error, root, script, args[3], arguments);
                rootCreated = true;
                process = new SafeFileHandle(child.Process, true);
                thread = new SafeFileHandle(child.Thread, true);
                output.CloseWriter();
                error.CloseWriter();
                bool inJob;
                Check(IsProcessInJob(process, job, out inJob));
                if (!inJob) throw new InvalidOperationException("Publication creation-time assignment absent");
                long created, exited, kernel, user;
                Check(GetProcessTimes(process, out created, out exited, out kernel, out user));
                uint rootSession;
                Check(ProcessIdToSessionId(child.ProcessId, out rootSession));
                if (created <= 0 || rootSession != session)
                    throw new InvalidOperationException("Publication suspended identity is unestablished");
                journal.Write("publication-root-suspended", "pid", child.ProcessId,
                    "creationFileTime", created.ToString(CultureInfo.InvariantCulture),
                    "session", rootSession, "inJob", true);
                if (fixture == "pre-resume")
                    throw new InvalidOperationException("Admitted pre-resume fixture fault");
                stage = "resume";
                CheckPublicationDeadline(root, workMilliseconds);
                // Latch before both intent persistence and ResumeThread; failure forbids killing.
                resumeAttempted = true;
                journal.Write("publication-resume-attempt", "resumeMayHaveRun", true);
                CheckPublicationDeadline(root, workMilliseconds);
                uint previousSuspendCount = ResumeThread(thread);
                if (fixture == "resume-unknown")
                {
                    while (!File.Exists(Path.Combine(root, "release")))
                    {
                        CheckPublicationDeadline(root, workMilliseconds);
                        Thread.Sleep(25);
                    }
                    CheckPublicationDeadline(root, workMilliseconds);
                    throw new InvalidOperationException("Admitted unknown-resume fixture fault");
                }
                if (previousSuspendCount == uint.MaxValue) throw new Win32Exception();
                resumed = true;
                if (previousSuspendCount != 1)
                    throw new InvalidOperationException("Unexpected publication suspend count");
                journal.Write("publication-resumed");
                thread.Dispose();
                thread = null;
                stage = "running";
                while (true)
                {
                    CheckPublicationDeadline(root, workMilliseconds);
                    output.Drain(ref captured);
                    error.Drain(ref captured);
                    SamplePublicationLifetime(job, process, rootCreated, lifetime);
                    if (lifetime.RootExited == true && lifetime.RootExitCode != 0)
                        throw new InvalidOperationException("Publication bootstrap failed");
                    if (lifetime.RootExited == true && lifetime.Active == 0 && output.Eof && error.Eof)
                    {
                        CheckPublicationDeadline(root, workMilliseconds);
                        completed = true;
                        break;
                    }
                    Thread.Sleep(25);
                }
            }
            catch (Exception caught) { failure = caught; }

            // One window for observation, audit, persistence and disposal; never restarted.
            long finalizationStarted = Clock.ElapsedMilliseconds;
            finalDeadline = Math.Min(totalMilliseconds, finalizationStarted + CleanupMilliseconds);
            journal.DeadlineMilliseconds = finalDeadline;
            bool failureAtFinalization = failure != null;
            long? passiveEnded = null;
            if (failure == null) stage = "finalization";
            try
            {
                if (failure != null && rootCreated && !resumeAttempted && process != null &&
                    Clock.ElapsedMilliseconds < finalDeadline)
                {
                    // Only the original, never-resumed process handle is eligible; never the Job.
                    neverResumedTerminationRequested = true;
                    neverResumedTerminationSucceeded = TerminateProcess(process, 1);
                    neverResumedTerminationError = neverResumedTerminationSucceeded ? 0 : Marshal.GetLastWin32Error();
                }
                long passiveDeadline = finalDeadline - PublicationAuditMilliseconds -
                    PublicationFinalRecordReserveMilliseconds;
                if (failureAtFinalization)
                {
                    while (Clock.ElapsedMilliseconds < passiveDeadline)
                    {
                        TryPublicationDrain(output, ref captured, ref failure);
                        if (Clock.ElapsedMilliseconds >= passiveDeadline) break;
                        TryPublicationDrain(error, ref captured, ref failure);
                        if (Clock.ElapsedMilliseconds >= passiveDeadline) break;
                        TryPublicationSample(job, process, rootCreated, lifetime, ref failure);
                        if ((!rootCreated || (lifetime.RootExited == true && lifetime.Active == 0)) &&
                            (output == null || output.Eof || output.FailureStage != null) &&
                            (error == null || error.Eof || error.FailureStage != null)) break;
                        Thread.Sleep(25);
                    }
                    passiveEnded = Clock.ElapsedMilliseconds;
                }
                audit = ObservePublicationMembers(job, finalDeadline -
                    PublicationFinalRecordReserveMilliseconds, memberHandles);
                if (!audit.Complete && failure == null)
                    failure = new InvalidOperationException("Publication member audit is incomplete");
                if (Clock.ElapsedMilliseconds < finalDeadline)
                    TryPublicationSample(job, process, rootCreated, lifetime, ref failure);
                else if (failure == null)
                    failure = new TimeoutException("Publication finalization expired");
                RecordPublicationAudit(journal, audit, finalDeadline, ref failure, ref evidenceIncomplete);
            }
            catch (Exception caught) { if (failure == null) failure = caught; }
            finally
            {
                // Hold Job/member handles through persistence. Stream closure is not exit proof.
                if (output != null) output.Dispose();
                if (error != null) error.Dispose();
                if (failure == null && output != null) failure = output.CloseFailure;
                if (failure == null && error != null) failure = error.CloseFailure;
                foreach (IDisposable input in inputs) ClosePublicationResource(input, ref failure);
                TryPublicationRecord(delegate { RecordCapture(journal, "stdout", output, "publication-capture"); }, finalDeadline, ref failure, ref evidenceIncomplete);
                TryPublicationRecord(delegate { RecordCapture(journal, "stderr", error, "publication-capture"); }, finalDeadline, ref failure, ref evidenceIncomplete);
                bool retained = PublicationLifetimeUnestablished(job, rootCreated, lifetime, audit) ||
                    evidenceIncomplete || journal.WriteFailed || Clock.ElapsedMilliseconds >= finalDeadline;
                TryPublicationRecord(delegate { journal.Write("publication-retention", "jobName", jobName,
                    "originalJobHandleHeld", job != null && !job.IsInvalid, "rootCreated", rootCreated,
                    "resumeAttempted", resumeAttempted, "resumed", resumed,
                    "neverResumedTerminationRequested", neverResumedTerminationRequested,
                    "neverResumedTerminationSucceeded", neverResumedTerminationSucceeded,
                    "neverResumedTerminationError", neverResumedTerminationError,
                    "neverResumedRootExitConfirmed", neverResumedTerminationRequested && lifetime.RootExited == true,
                    "rootExited", lifetime.RootExited, "rootExitCode", lifetime.RootExitCode,
                    "activeProcesses", lifetime.Active, "totalProcesses", lifetime.Total,
                    "lastLifetimeSampleMilliseconds", lifetime.SampleMilliseconds,
                    "lifetimeFailureType", lifetime.FailureType, "auditComplete", audit.Complete,
                    "stdoutEof", output == null ? (object)null : output.Eof,
                    "stderrEof", error == null ? (object)null : error.Eof,
                    "retainedLiveWorkOrUnknown", retained, "failureLatched", failure != null,
                    "evidenceIncomplete", evidenceIncomplete || journal.WriteFailed,
                    "completionObserved", completed, "failureAtFinalization", failureAtFinalization,
                    "finalizationStartedMilliseconds", finalizationStarted,
                    "passiveEndedMilliseconds", passiveEnded,
                    "finalDeadlineMilliseconds", finalDeadline, "terminationAfterResumeAttempt", false,
                    "nameRecoveryAfterCloseGuaranteed", false); }, finalDeadline, ref failure, ref evidenceIncomplete);
                foreach (SafeFileHandle handle in memberHandles) ClosePublicationResource(handle, ref failure);
                ClosePublicationResource(thread, ref failure);
                ClosePublicationResource(process, ref failure);
                // End the operating interval without kill-on-close, even with survivors.
                ClosePublicationResource(job, ref failure);
            }
            if (Clock.ElapsedMilliseconds >= finalDeadline && failure == null)
                failure = new TimeoutException("Publication finalization exceeded its original bound");
            bool liveOrUnknown = PublicationLifetimeUnestablished(job, rootCreated, lifetime, audit) ||
                evidenceIncomplete || journal.WriteFailed || Clock.ElapsedMilliseconds >= finalDeadline;
            TryPublicationRecord(delegate { journal.Write("publication-operating-interval-end", "jobName", jobName,
                "jobHandleClosed", job == null || job.IsClosed, "retainedLiveWorkOrUnknown", liveOrUnknown,
                "nameRecoveryAfterCloseGuaranteed", false, "finalDeadlineMilliseconds", finalDeadline); }, finalDeadline, ref failure, ref evidenceIncomplete);
            if (failure != null)
            {
                Exception first = failure;
                TryPublicationRecord(delegate { journal.Write("publication-failed", "stage", stage,
                    "resumeAttempted", resumeAttempted, "failureType", first.GetType().Name,
                    "hresult", first.HResult); }, finalDeadline, ref failure, ref evidenceIncomplete);
            }
            liveOrUnknown = liveOrUnknown || evidenceIncomplete || journal.WriteFailed;
            completionReady = completed && failure == null && !liveOrUnknown;
            TryPublicationRecord(delegate { journal.Write("publication-launcher-exit", "readyForExit", completionReady,
                "retainedLiveWorkOrUnknown", liveOrUnknown, "capturedBytes", captured); }, finalDeadline, ref failure, ref evidenceIncomplete);
            if (Clock.ElapsedMilliseconds >= finalDeadline && failure == null)
                failure = new TimeoutException("Publication reporting exceeded its original bound");
            if (failure != null)
                TryPublicationRecord(delegate { Console.Error.WriteLine("Publication launcher failed in {0}: {1}; HRESULT={2}; retainedLiveWorkOrUnknown={3}; resumeAttempted={4}",
                    stage, failure.GetType().Name, failure.HResult.ToString(CultureInfo.InvariantCulture),
                    liveOrUnknown || evidenceIncomplete || journal.WriteFailed || Clock.ElapsedMilliseconds >= finalDeadline,
                    resumeAttempted); }, finalDeadline, ref failure, ref evidenceIncomplete);
        }
        catch (Exception caught) { if (failure == null) failure = caught; }
        finally
        {
            ClosePublicationResource(journal, ref failure);
            ClosePublicationResource(scripts, ref failure);
            ClosePublicationResource(directory, ref failure);
        }
        // A prior readyForExit record is provisional until all owned disposal finishes.
        if (Clock.ElapsedMilliseconds >= finalDeadline && failure == null)
            failure = new TimeoutException("Publication disposal exceeded its original bound");
        return completionReady && failure == null ? 0 : 1;
    }

    private sealed class PublicationLifetime
    {
        public bool? RootExited;
        public uint? RootExitCode, Active, Total;
        public long? SampleMilliseconds;
        public string FailureType;
    }

    private sealed class PublicationMember
    {
        public uint Pid;
        public string CreationFileTime, ImageName;
        public bool? InJob;
        public string Status = "open-failed";
        public int? NativeError;
    }

    private sealed class PublicationAudit
    {
        public bool Complete, QuerySucceeded;
        public uint? Assigned, Returned, ReturnedBytes;
        public int? QueryError;
        public string Status = "not-attempted";
        public long StartedMilliseconds, EndedMilliseconds;
        public readonly List<PublicationMember> Members = new List<PublicationMember>();
    }

    private static void CheckPublicationDeadline(string root, int workMilliseconds)
    {
        if (Clock.ElapsedMilliseconds >= workMilliseconds)
            throw new TimeoutException("Original publication launcher deadline expired");
        if (File.Exists(Path.Combine(root, "cancel")))
            throw new OperationCanceledException("Publication cancellation marker observed");
    }

    private static void SamplePublicationLifetime(SafeFileHandle job, SafeFileHandle process,
        bool rootCreated, PublicationLifetime value)
    {
        // Reset stale observations before resampling.
        value.RootExited = null; value.RootExitCode = null; value.Active = null; value.Total = null;
        value.SampleMilliseconds = Clock.ElapsedMilliseconds; value.FailureType = null;
        try
        {
            if (!rootCreated) value.RootExited = true;
            else
            {
                if (process == null || process.IsInvalid)
                    throw new InvalidOperationException("Original publication process handle unavailable");
                value.RootExited = HasExited(process);
                if (value.RootExited == true)
                {
                    uint code;
                    Check(GetExitCodeProcess(process, out code));
                    value.RootExitCode = code;
                }
            }
            if (job != null && !job.IsInvalid)
            {
                Accounting accounting = Query(job);
                value.Active = accounting.ActiveProcesses;
                value.Total = accounting.TotalProcesses;
            }
            else if (rootCreated)
                throw new InvalidOperationException("Original publication Job handle unavailable");
        }
        catch (Exception caught) { value.FailureType = caught.GetType().Name; throw; }
    }

    private static void TryPublicationSample(SafeFileHandle job, SafeFileHandle process,
        bool rootCreated, PublicationLifetime value, ref Exception failure)
    {
        try { SamplePublicationLifetime(job, process, rootCreated, value); }
        catch (Exception caught) { if (failure == null) failure = caught; }
    }

    private static void TryPublicationDrain(Pipe pipe, ref int captured, ref Exception failure)
    {
        if (pipe == null || pipe.Eof || pipe.FailureStage != null) return;
        try { pipe.Drain(ref captured); }
        catch (Exception caught) { if (failure == null) failure = caught; }
    }

    private static bool PublicationLifetimeUnestablished(SafeFileHandle job, bool rootCreated,
        PublicationLifetime lifetime, PublicationAudit audit)
    {
        if (!rootCreated && (job == null || job.IsInvalid)) return false;
        return lifetime.FailureType != null || lifetime.RootExited != true || lifetime.Active != 0 ||
            !audit.Complete;
    }

    private static void ClosePublicationResource(IDisposable resource, ref Exception failure)
    {
        if (resource == null) return;
        try { resource.Dispose(); }
        catch (Exception caught) { if (failure == null) failure = caught; }
    }

    private static void TryPublicationRecord(Action record, long deadline, ref Exception failure, ref bool incomplete)
    {
        if (!PublicationRecordTime(deadline, ref failure, ref incomplete)) return;
        try { record(); }
        catch (Exception caught) { incomplete = true; if (failure == null) failure = caught; }
        finally { PublicationRecordTime(deadline, ref failure, ref incomplete); }
    }

    private static bool PublicationRecordTime(long deadline, ref Exception failure, ref bool incomplete)
    {
        if (Clock.ElapsedMilliseconds < deadline) return true;
        incomplete = true;
        if (failure == null) failure = new TimeoutException("Publication evidence deadline");
        return false;
    }

    // Guard's fixed-32 non-atomic pattern; retain original Job and member handles.
    private static PublicationAudit ObservePublicationMembers(SafeFileHandle job, long outerDeadline,
        List<SafeFileHandle> retained)
    {
        var result = new PublicationAudit();
        result.StartedMilliseconds = Clock.ElapsedMilliseconds;
        long deadline = Math.Min(outerDeadline, result.StartedMilliseconds + PublicationAuditMilliseconds);
        Func<bool> hasTime = delegate { return Clock.ElapsedMilliseconds < deadline; };
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!hasTime()) { result.Status = "deadline"; return result; }
            if (job == null || job.IsInvalid)
            {
                result.Status = "no-created-job";
                result.Complete = true;
                return result;
            }
            buffer = Marshal.AllocHGlobal(8 + 32 * IntPtr.Size);
            uint written;
            bool queried = QueryInformationJobObject(job, 3, buffer, (uint)(8 + 32 * IntPtr.Size), out written);
            int queryError = Marshal.GetLastWin32Error();
            if (!queried)
            {
                result.QueryError = queryError; result.Status = "query-failed";
                return result;
            }
            result.QuerySucceeded = true;
            result.ReturnedBytes = written;
            uint assigned = unchecked((uint)Marshal.ReadInt32(buffer, 0));
            uint returned = unchecked((uint)Marshal.ReadInt32(buffer, 4));
            result.Assigned = assigned; result.Returned = returned;
            if (assigned > 32 || returned > 32 || assigned != returned ||
                written < 8 + returned * IntPtr.Size || written > 8 + 32 * IntPtr.Size)
            {
                result.Status = "membership-list-incomplete";
                return result;
            }
            bool complete = true;
            var seen = new HashSet<uint>();
            for (int index = 0; index < returned; index++)
            {
                if (!hasTime()) { result.Status = "deadline"; return result; }
                ulong rawPid = unchecked((ulong)Marshal.ReadIntPtr(buffer, 8 + index * IntPtr.Size).ToInt64());
                if (rawPid == 0 || rawPid > uint.MaxValue || !seen.Add((uint)rawPid))
                {
                    result.Status = "invalid-pid-list";
                    return result;
                }
                var member = new PublicationMember();
                member.Pid = (uint)rawPid;
                result.Members.Add(member);
                if (!hasTime()) { member.Status = "deadline"; result.Status = "deadline"; return result; }
                SafeFileHandle handle = OpenProcess(0x1000u, false, member.Pid);
                int openError = Marshal.GetLastWin32Error();
                if (handle.IsInvalid)
                {
                    handle.Dispose(); member.NativeError = openError; complete = false; continue;
                }
                retained.Add(handle);
                long creation, exited, kernel, user;
                bool inJob;
                if (!hasTime()) { member.Status = "deadline"; result.Status = "deadline"; return result; }
                if (!GetProcessTimes(handle, out creation, out exited, out kernel, out user))
                {
                    member.NativeError = Marshal.GetLastWin32Error(); member.Status = "time-failed";
                    complete = false; continue;
                }
                if (creation <= 0) { member.Status = "invalid-time"; complete = false; continue; }
                member.CreationFileTime = creation.ToString(CultureInfo.InvariantCulture);
                if (!hasTime()) { member.Status = "deadline"; result.Status = "deadline"; return result; }
                if (!IsProcessInJob(handle, job, out inJob))
                {
                    member.NativeError = Marshal.GetLastWin32Error(); member.Status = "membership-failed";
                    complete = false; continue;
                }
                member.InJob = inJob;
                if (!inJob) { member.Status = "not-member"; complete = false; continue; }
                var image = new StringBuilder(32768);
                uint capacity = 32768;
                if (!hasTime()) { member.Status = "deadline"; result.Status = "deadline"; return result; }
                if (!QueryFullProcessImageName(handle, 0, image, ref capacity))
                {
                    member.NativeError = Marshal.GetLastWin32Error(); member.Status = "image-failed";
                    complete = false; continue;
                }
                string basename = Path.GetFileName(image.ToString());
                if (basename.Length == 0 || basename.Length > 260)
                { member.Status = "image-limit"; complete = false; continue; }
                member.ImageName = basename; member.Status = "observed-member";
            }
            result.Complete = complete && hasTime();
            result.Status = result.Complete ? "observed" : hasTime() ? "member-incomplete" : "deadline";
            return result;
        }
        catch (Exception caught)
        {
            result.Complete = false; result.Status = caught.GetType().Name;
            return result;
        }
        finally
        {
            result.EndedMilliseconds = Clock.ElapsedMilliseconds;
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void RecordPublicationAudit(Journal journal, PublicationAudit audit, long deadline,
        ref Exception failure, ref bool incomplete)
    {
        foreach (PublicationMember member in audit.Members)
        {
            if (Clock.ElapsedMilliseconds >= deadline)
            {
                incomplete = true;
                if (failure == null) failure = new TimeoutException("Publication audit persistence deadline");
                break;
            }
            PublicationMember observed = member;
            TryPublicationRecord(delegate { journal.Write("publication-audit-member", "pid", observed.Pid,
                "creationFileTime", observed.CreationFileTime, "inJob", observed.InJob,
                "imageName", observed.ImageName, "status", observed.Status,
                "nativeError", observed.NativeError); }, deadline, ref failure, ref incomplete);
        }
        TryPublicationRecord(delegate { journal.Write("publication-audit", "atomic", false, "limit", 32,
            "complete", audit.Complete, "querySucceeded", audit.QuerySucceeded,
            "assigned", audit.Assigned, "returned", audit.Returned, "returnedBytes", audit.ReturnedBytes,
            "queryError", audit.QueryError, "status", audit.Status,
            "startedMilliseconds", audit.StartedMilliseconds, "endedMilliseconds", audit.EndedMilliseconds); },
            deadline, ref failure, ref incomplete);
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

    private static void RecordCapture(Journal journal, string stream, Pipe pipe, string kind = "capture")
    {
        if (pipe == null) { journal.Write(kind, "stream", stream, "initialized", false); return; }
        journal.Write(kind, "stream", stream, "initialized", true,
            "readBytes", pipe.ReadBytes, "confirmedFlushedBytes", pipe.ConfirmedFlushedBytes,
            "eof", pipe.Eof, "overflowDetected", pipe.OverflowDetected,
            "failureStage", pipe.FailureStage, "failureType", pipe.FailureType,
            "failureHresult", pipe.FailureHresult, "failureNativeError", pipe.FailureNativeError,
            "closeFailureType", pipe.CloseFailure == null ? null : pipe.CloseFailure.GetType().Name);
    }

    private static ProcessInformation StartSuspended(SafeFileHandle job, Pipe output, Pipe error,
        string root, string script, string authorityHash)
    {
        return StartSuspended(job, output, error, root, script, authorityHash,
            "-Mode Controller -AuthoritySha256 " + authorityHash);
    }

    private static ProcessInformation StartSuspended(SafeFileHandle job, Pipe output, Pipe error,
        string root, string script, string authorityHash, string arguments)
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
                    script + "\" " + arguments;
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
        private readonly int maximum;
        public bool WriteFailed { get; private set; }
        public long? DeadlineMilliseconds { get; set; }
        public Journal(string path, int maximum = 16384)
        {
            this.maximum = maximum;
            file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        }
        public void Write(string kind, params object[] fields)
        {
            try { WriteRecord(kind, fields); }
            catch { WriteFailed = true; throw; }
        }
        private void WriteRecord(string kind, object[] fields)
        {
            var text = new StringBuilder("{\"event\":").Append(Json(kind));
            text.Append(",\"elapsedMilliseconds\":").Append(Clock.ElapsedMilliseconds.ToString(CultureInfo.InvariantCulture));
            for (int index = 0; index < fields.Length; index += 2)
                text.Append(',').Append(Json((string)fields[index])).Append(':').Append(Json(fields[index + 1]));
            byte[] bytes = Encoding.UTF8.GetBytes(text.Append("}\n").ToString());
            CheckWriteTime();
            if (file.Length + bytes.Length > maximum) throw new InvalidOperationException("Journal size limit");
            CheckWriteTime();
            file.Write(bytes, 0, bytes.Length);
            CheckWriteTime();
            file.Flush(true);
            CheckWriteTime();
        }
        private void CheckWriteTime()
        {
            if (DeadlineMilliseconds.HasValue && Clock.ElapsedMilliseconds >= DeadlineMilliseconds.Value)
                throw new TimeoutException("Journal deadline");
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
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, IntPtr information, uint size, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(SafeFileHandle process, SafeFileHandle job, out bool inJob);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(IntPtr process, SafeFileHandle job, out bool inJob);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(SafeFileHandle process, uint flags, StringBuilder name, ref uint size);
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
