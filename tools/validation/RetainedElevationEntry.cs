// Retained validation entry; one separately admitted attended activation only.
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

internal static class RetainedElevationEntry
{
    private static readonly bool ExecutionAdmitted = false;
    private const string Wsl = @"C:\Windows\System32\wsl.exe";
    private const int OutputLimit = 16384;
    private static long WorkMilliseconds;
    private static long TotalMilliseconds;
    private static DateTime AbsoluteDeadline;
    private static DateTime ClockPinnedUtc;
    private static long ClockPinnedElapsed;
    private static long MaximumElapsed;
    private static readonly ulong Started = GetTickCount64();
    private static long Elapsed
    {
        get
        {
            long ticks = checked((long)(GetTickCount64() - Started));
            if (ClockPinnedUtc == default(DateTime)) return ticks;
            long wall = ClockPinnedElapsed + (long)(DateTime.UtcNow - ClockPinnedUtc).TotalMilliseconds;
            MaximumElapsed = Math.Max(MaximumElapsed, Math.Max(ticks, wall));
            return MaximumElapsed; // Neither clock rollback nor suspend renews elapsed time.
        }
    }

    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted) return 125;
        try
        {
            // Fixed first-failed-check statuses survive the existing proxyExit capture.
            // Preserve ordered input admission; never emit rejected input values.
            if (args.Length != 4) return 101;
            if (args[0] != "--launch" && args[0] != "--entry" && args[0] != "--context-check" &&
                args[0] != "--input-check") return 102;
            if (!Regex.IsMatch(args[1], @"\AC:\\Temp\\azureauth-windows-slice-108\\elevation-entry-[0-9]{4}\z")) return 103;
            if (!Regex.IsMatch(args[2], @"\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z")) return 104;
            if (!IsHash(args[3])) return 105;
            string root = args[1], nonce = args[2];
            using (SafeFileHandle directory = OpenDirectory(root))
            using (FileStream manifest = Pin(Path.Combine(root, "entry-inputs.txt"), args[3], 65536))
            {
                string[] inputs = ReadText(manifest).Split('\n');
                if (inputs.Length != 13) return 110;
                if (inputs[0] != "azureauth-retained-elevation-v2") return 111;
                if (inputs[1] != nonce) return 112;
                if (inputs[11] != "END") return 113;
                if (inputs[12] != "") return 114;
                if (!Regex.IsMatch(inputs[2], @"\A[A-Za-z0-9_.-]{1,64}\z")) return 115;
                if (!Regex.IsMatch(inputs[3], @"\A[a-z_][a-z0-9_-]{0,63}\z")) return 116;
                if (!Regex.IsMatch(inputs[4], @"\A[1-9][0-9]{0,8}\z")) return 117;
                if (!IsHash(inputs[5])) return 118;
                if (!IsHash(inputs[6])) return 119;
                if (!IsHash(inputs[7])) return 120;
                if (!Regex.IsMatch(inputs[8], @"\A/run/WSL/[1-9][0-9]*_interop\z")) return 121;
                if (inputs[9] != "/var/tmp/azureauth-windows-slice-108/elevation-entry-" + root.Substring(root.Length - 4)) return 122;
                if (!Regex.IsMatch(inputs[10], @"\A[1-9][0-9]{16,18}\z")) return 127;
                AbsoluteDeadline = DateTime.FromFileTimeUtc(long.Parse(inputs[10], CultureInfo.InvariantCulture));
                ClockPinnedElapsed = checked((long)(GetTickCount64() - Started));
                ClockPinnedUtc = DateTime.UtcNow;
                long remaining = (long)(AbsoluteDeadline - ClockPinnedUtc).TotalMilliseconds;
                long minimum = args[0] == "--context-check" ? 20000 : args[0] == "--entry" ? 90000 : 220000;
                if (remaining < minimum || remaining > 86400000) return 128;
                TotalMilliseconds = Math.Min(86400000, ClockPinnedElapsed + remaining);
                WorkMilliseconds = TotalMilliseconds - 10000;
                AssertDirect(root);
                string image = Path.Combine(root, "RetainedElevationEntry.exe");
                using (FileStream ownImage = Pin(image, inputs[7], 2097152))
                using (FileStream holder = Pin(Path.Combine(root, "retained_elevation_holder.py"), inputs[6], 65536))
                {
                    using (Process self = Process.GetCurrentProcess())
                    {
                        using (SafeFileHandle current = OpenProcess(0x1000u, false, (uint)self.Id))
                        {
                            if (current.IsInvalid) return 123;
                            int reason = AdmitImage(current, image, ownImage);
                            if (reason != 0) return reason == 129 ? 126 : reason;
                        }
                    }
                    if (TotalMilliseconds - Elapsed < minimum) return 128;
                    // Input validation ends before any launch, token, child or marker operation.
                    if (args[0] == "--input-check") return 0;
                    if (args[0] == "--launch") return Launch(root, nonce, args[3], ownImage);
                    if (args[0] == "--context-check") return Context(root, nonce);
                    using (FileStream permit = OpenRead(Path.Combine(root, "launch-permit.txt"), 256))
                    {
                        string[] grant = ReadText(permit).Split('\n');
                        if (grant.Length != 4 || grant[0] != nonce || grant[3] != "" ||
                            GetTickCount64() >= ulong.Parse(grant[1], CultureInfo.InvariantCulture) ||
                            DateTime.UtcNow.ToFileTimeUtc() >= long.Parse(grant[2], CultureInfo.InvariantCulture) ||
                            StopRequested(root, nonce)) return 1;
                    }
                    if (TotalMilliseconds - Elapsed < 90000) return 128;
                    return Run(root, nonce, args[3], inputs, ownImage);
                }
            }
        }
        catch { return 1; } // No exception text, account identifiers or environment dump.
    }

    private static int Launch(string root, string nonce, string manifestHash, FileStream ownImage)
    {
        // One UAC request. The worker thread is not an extra process or command service.
        SafeFileHandle entry = null;
        Exception launchFailure = null;
        bool completed = false, abandoned = false;
        object gate = new object();
        using (Journal journal = new Journal(Path.Combine(root, "launcher.jsonl"), 16384))
        {
            using (Process self = Process.GetCurrentProcess())
                journal.Write("launcher-start", "pid", self.Id, "creationFileTime",
                    self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture),
                    "nonce", nonce, "elevated", Elevated(self.Handle),
                    "deadlineFileTime", AbsoluteDeadline.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture));
            CreateText(Path.Combine(root, "launch-permit.txt"), nonce + "\n" +
                (GetTickCount64() + 120000UL).ToString(CultureInfo.InvariantCulture) + "\n" +
                DateTime.UtcNow.AddSeconds(120).ToFileTimeUtc().ToString(CultureInfo.InvariantCulture) + "\n");
            var request = new Thread(delegate()
            {
                bool initialized = false;
                try
                {
                    int code = CoInitializeEx(IntPtr.Zero, 6); // APARTMENTTHREADED | DISABLE_OLE1DDE
                    if (code < 0) Marshal.ThrowExceptionForHR(code);
                    initialized = true;
                    var info = new ShellInformation();
                    info.Size = Marshal.SizeOf(info);
                    info.Mask = 0x40u | 0x100u | 0x400u; // NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI
                    info.Verb = "runas";
                    info.File = Path.Combine(root, "RetainedElevationEntry.exe");
                    info.Parameters = "--entry " + root + " " + nonce + " " + manifestHash;
                    info.Directory = root;
                    info.Show = 1;
                    Check(ShellExecuteEx(ref info));
                    var created = new SafeFileHandle(info.Process, true);
                    lock (gate)
                    {
                        if (abandoned) created.Dispose();
                        else entry = created;
                    }
                }
                catch (Exception caught) { lock (gate) { launchFailure = caught; } }
                finally
                {
                    if (initialized) CoUninitialize();
                    lock (gate) { completed = true; }
                }
            });
            request.IsBackground = true;
            request.SetApartmentState(ApartmentState.STA);
            request.Start();
            while (Elapsed < 120000)
            {
                lock (gate) { if (completed) break; }
                Thread.Sleep(1000);
            }
            lock (gate)
            {
                if (!completed)
                {
                    abandoned = true;
                    RequestStop(root, nonce);
                    journal.Write("launcher-final", "entryLifetimeKnown", false, "failure", "UacRequestDeadline");
                    return 1;
                }
            }
            if (entry == null || entry.IsInvalid)
            {
                RequestStop(root, nonce);
                journal.Write("launcher-final", "entryHandleReturned", false,
                    "failureType", launchFailure == null ? null : launchFailure.GetType().Name);
                if (entry != null) entry.Dispose();
                return 1;
            }
            using (entry)
            {
                bool imageAccepted = false, nativeExited = false;
                bool? nativeExitSample = null;
                uint? exitCode = null;
                Exception failure = null;
                int rejection = 0;
                try
                {
                    long created, exited, kernel, user;
                    Check(GetProcessTimes(entry, out created, out exited, out kernel, out user));
                    rejection = AdmitImage(entry, Path.Combine(root, "RetainedElevationEntry.exe"), ownImage);
                    if (rejection != 0) throw new GuardFailure(rejection);
                    imageAccepted = true;
                    journal.Write("entry-handle", "creationFileTime", created.ToString(CultureInfo.InvariantCulture));
                    while (!HasExited(entry) && Elapsed < WorkMilliseconds && !StopRequested(root, nonce))
                        Thread.Sleep(1000);
                }
                catch (Exception caught)
                {
                    failure = caught;
                    if (rejection == 0 && caught is Win32Exception) rejection = 141;
                    if (rejection == 0 && caught is IOException) rejection = 142;
                }
                finally
                {
                    // ShellExecuteEx directly returned this task's held launch handle.
                    // Rejected admission permits bounded observation and scoped stop, never arbitrary termination.
                    long finalEnd = Math.Min(TotalMilliseconds, Elapsed + 10000);
                    try { RequestStop(root, nonce); }
                    catch (Exception caught) { if (failure == null) failure = caught; }
                    try
                    {
                        while (!HasExited(entry) && Elapsed < finalEnd) Thread.Sleep(25);
                        nativeExited = HasExited(entry);
                        nativeExitSample = nativeExited;
                        if (nativeExited)
                        {
                            uint code;
                            Check(GetExitCodeProcess(entry, out code));
                            exitCode = code;
                        }
                    }
                    catch (Exception caught) { if (failure == null) failure = caught; }
                    journal.DeadlineMilliseconds = TotalMilliseconds;
                    journal.Write("launcher-final", "entryHandleReturned", true,
                        "entryImageAccepted", imageAccepted, "entryNativeExited", nativeExitSample,
                        "entryExitCode", exitCode, "entryLifetimeKnown", nativeExited,
                        "rejectionReason", rejection,
                        "failureType", failure == null ? null : failure.GetType().Name);
                }
                return imageAccepted && nativeExited && exitCode == 0 && failure == null ? 0 : 1;
            }
        }
    }

    private static int Context(string root, string nonce)
    {
        using (Process self = Process.GetCurrentProcess())
        using (EventWaitHandle release = EventWaitHandle.OpenExisting(EventName(nonce),
            System.Security.AccessControl.EventWaitHandleRights.Synchronize))
        {
            bool elevated = Elevated(self.Handle);
            string content = nonce + "\n" + self.Id.ToString(CultureInfo.InvariantCulture) + "\n" +
                self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture) + "\n" +
                (elevated ? "1\n" : "0\n");
            CreateText(Path.Combine(root, "context-created.txt"), content);
            Directory.CreateDirectory(Path.Combine(root, "context-ready"));
            // Parent opens and validates this incarnation before releasing it.
            bool released = release.WaitOne(10000);
            return elevated && released && Elapsed < 15000 ? 0 : 1;
        }
    }

    private static int Run(string root, string nonce, string manifestHash, string[] inputs, FileStream ownImage)
    {
        SafeFileHandle job = null, process = null, thread = null, context = null;
        Pipe output = null, error = null;
        int captured = 0;
        bool ready = false, resumeAttempted = false, clean = false, contextOwned = false;
        bool contextAcquired = false, contextCreationMatched = false, contextReleaseRequested = false;
        bool? contextExitObserved = null;
        uint? contextObservedExitCode = null;
        int rejectionReason = 0;
        Exception failure = null;
        string stage = "entry";
        long created = 0;
        uint wslPid = 0;
        DateTime deadline = AbsoluteDeadline;
        using (Journal journal = new Journal(Path.Combine(root, "entry.jsonl"), 65536))
        {
            bool newEvent;
            using (EventWaitHandle release = new EventWaitHandle(false, EventResetMode.ManualReset, EventName(nonce), out newEvent))
            {
                try
                {
                    if (!newEvent) throw new InvalidOperationException("Existing entry event");
                    using (Process self = Process.GetCurrentProcess())
                    {
                        bool elevated = Elevated(self.Handle);
                        journal.Write("entry-start", "pid", self.Id, "creationFileTime",
                            self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture),
                            "elevated", elevated, "nonce", nonce, "manifestSha256", manifestHash,
                            "deadlineUtc", deadline.ToString("O", CultureInfo.InvariantCulture),
                            "deadlineFileTime", deadline.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture), "jobName", JobName(nonce));
                        if (!elevated) throw new InvalidOperationException("Entry is not elevated");
                    }
                    foreach (string leaf in new[] { "stop", "context-created.txt", "context-ready", "linux-ready", "entry-ready.json", "entry-ready" })
                        if (File.Exists(Path.Combine(root, leaf)) || Directory.Exists(Path.Combine(root, leaf))) throw new InvalidOperationException("Occupied entry output");
                    stage = "job-create";
                    job = CreateJobObject(IntPtr.Zero, JobName(nonce));
                    int code = Marshal.GetLastWin32Error();
                    if (job.IsInvalid) throw new Win32Exception(code);
                    if (code == 183) { job.Dispose(); job = null; throw new InvalidOperationException("Existing entry Job"); }
                    var limits = new ExtendedLimits();
                    limits.Basic.LimitFlags = 0x2008;
                    limits.Basic.ActiveProcessLimit = 32;
                    Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)));
                    using (SafeFileHandle reopened = OpenJobObject(0xCu, false, JobName(nonce)))
                        if (reopened.IsInvalid) throw new Win32Exception();
                    journal.Write("job-ready", "queryAndTerminateAccess", true, "killOnClose", true, "activeLimit", 32);
                    output = new Pipe(Path.Combine(root, "wsl.stdout.bin"));
                    error = new Pipe(Path.Combine(root, "wsl.stderr.bin"));
                    string projected = "/mnt/c/Temp/azureauth-windows-slice-108/" + Path.GetFileName(root);
                    string runtime = "/run/user/" + inputs[4];
                    stage = "wsl-create";
                    using (FileStream wslInput = Pin(Wsl, inputs[5], 2097152))
                    {
                        if (TotalMilliseconds - Elapsed < 70000) throw new TimeoutException("Startup budget");
                        string command = "\"" + Wsl + "\" --distribution " + inputs[2] + " --user " + inputs[3] +
                            " --cd " + projected + " --exec /usr/bin/env XDG_RUNTIME_DIR=" + runtime +
                            " DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtime + "/bus /usr/bin/systemd-run --user --no-ask-password" +
                            " --quiet --scope --collect --unit=" + Scope(nonce) +
                            " --property=RuntimeMaxSec=" + Math.Max(1, (WorkMilliseconds - Elapsed - 10000) / 1000).ToString(CultureInfo.InvariantCulture) +
                            "s --property=TimeoutStopSec=5s --property=TasksMax=32 --property=MemoryMax=512M" +
                            " -- /usr/bin/python3.14 -I -B -S " + projected + "/retained_elevation_holder.py " +
                            nonce + " " + manifestHash + " " + deadline.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture);
                        ProcessInformation child = StartWsl(job, output, error, root, command);
                        process = new SafeFileHandle(child.Process, true);
                        thread = new SafeFileHandle(child.Thread, true);
                        wslPid = child.ProcessId;
                        output.CloseWriter(); error.CloseWriter();
                        bool inJob;
                        Check(IsProcessInJob(process, job, out inJob));
                        long exited, kernel, user;
                        Check(GetProcessTimes(process, out created, out exited, out kernel, out user));
                        if (!inJob || created <= 0) throw new InvalidOperationException("Wsl creation identity");
                        journal.Write("wsl-suspended", "pid", wslPid, "creationFileTime", created.ToString(CultureInfo.InvariantCulture), "inJob", inJob);
                        stage = "resume";
                        resumeAttempted = true;
                        journal.Write("resume-requested");
                        if (ResumeThread(thread) != 1) throw new Win32Exception();
                        thread.Dispose(); thread = null;
                        stage = "context";
                        long startupEnd = Math.Min(60000, WorkMilliseconds);
                        WaitForMarker(root, "context-ready", nonce, startupEnd, process, output, error, ref captured);
                        string[] fields;
                        using (FileStream record = OpenRead(Path.Combine(root, "context-created.txt"), 512))
                            fields = ReadText(record).Split('\n');
                        if (fields.Length != 5 || fields[0] != nonce || (fields[3] != "0" && fields[3] != "1") || fields[4] != "")
                            throw new InvalidOperationException("Context record");
                        uint contextPid = uint.Parse(fields[1], CultureInfo.InvariantCulture);
                        if (contextPid == 0) throw new InvalidOperationException("Context PID");
                        long expectedCreated = long.Parse(fields[2], CultureInfo.InvariantCulture);
                        context = OpenProcess(0x101001u, false, contextPid); // QUERY_LIMITED | SYNCHRONIZE | TERMINATE
                        if (context.IsInvalid) throw new Win32Exception();
                        contextAcquired = true;
                        long actualCreated;
                        Check(GetProcessTimes(context, out actualCreated, out exited, out kernel, out user));
                        if (actualCreated != expectedCreated) throw new GuardFailure(140);
                        contextCreationMatched = true;
                        int contextReason = AdmitImage(context, Path.Combine(root, "RetainedElevationEntry.exe"), ownImage);
                        if (contextReason != 0) throw new GuardFailure(contextReason);
                        contextOwned = true;
                        bool contextElevated = fields[3] == "1";
                        journal.Write("context-handle", "pid", contextPid, "creationFileTime", fields[2], "elevated", contextElevated);
                        contextReleaseRequested = true;
                        release.Set();
                        long contextEnd = Math.Min(startupEnd, Elapsed + 5000);
                        while (!HasExited(context) && Elapsed < contextEnd) Thread.Sleep(25);
                        uint contextExit;
                        if (!HasExited(context)) throw new TimeoutException("Context exit");
                        Check(GetExitCodeProcess(context, out contextExit));
                        contextExitObserved = true;
                        contextObservedExitCode = contextExit;
                        journal.Write("context-exit", "nativeExited", true, "exitCode", contextExit);
                        if (contextExit != 0 || !contextElevated) throw new InvalidOperationException("Context failed");
                        WaitForMarker(root, "linux-ready", nonce, startupEnd, process, output, error, ref captured);
                        using (Journal marker = new Journal(Path.Combine(root, "entry-ready.json"), 4096))
                            marker.Write("entry-ready", "nonce", nonce, "contextElevated", true,
                                "contextNativeExited", true, "jobName", JobName(nonce), "scope", Scope(nonce),
                                "deadlineUtc", deadline.ToString("O", CultureInfo.InvariantCulture),
                                "deadlineFileTime", deadline.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture));
                        Directory.CreateDirectory(Path.Combine(root, "entry-ready"));
                        ready = true;
                        stage = "retained";
                        while (Elapsed < WorkMilliseconds && !StopRequested(root, nonce))
                        {
                            output.Drain(ref captured); error.Drain(ref captured);
                            if (HasExited(process)) throw new InvalidOperationException("Entry Wsl exited early");
                            Thread.Sleep(1000);
                        }
                    }
                }
                catch (Exception caught)
                {
                    failure = caught;
                    var guard = caught as GuardFailure;
                    if (guard != null) rejectionReason = guard.Reason;
                    else if (caught is Win32Exception) rejectionReason = 141;
                    else if (caught is IOException) rejectionReason = 142;
                }
                finally
                {
                    long finalEnd = Math.Min(TotalMilliseconds, Elapsed + 10000);
                    try
                    {
                        RequestStop(root, nonce);
                        journal.Write("stop-requested", "ready", ready, "stage", stage);
                    }
                    catch (Exception caught) { if (failure == null) failure = caught; }
                    // Signal the fixed Linux holder before ending the native WSL client.
                    // The original Linux transport also stops this exact scope on failure.
                    if (contextOwned)
                    {
                        try
                        {
                            contextReleaseRequested = true;
                            release.Set();
                            if (!HasExited(context))
                            {
                                Thread.Sleep(50);
                                if (!HasExited(context)) Check(TerminateProcess(context, 1));
                            }
                        }
                        catch (Exception caught) { if (failure == null) failure = caught; }
                    }
                    if (process != null && job != null)
                    {
                        try
                        {
                            while (Elapsed < finalEnd - 2000)
                            {
                                if (output.FailureStage == null) { try { output.Drain(ref captured); } catch { } }
                                if (error.FailureStage == null) { try { error.Drain(ref captured); } catch { } }
                                if (HasExited(process) && Query(job).ActiveProcesses == 0 && output.Eof && error.Eof) break;
                                Thread.Sleep(100);
                            }
                            if (!HasExited(process) || Query(job).ActiveProcesses != 0)
                            {
                                journal.Write("job-termination-requested", "linuxClosureNotEstablished", resumeAttempted);
                                Check(TerminateJobObject(job, 1));
                            }
                            while (Elapsed < finalEnd)
                            {
                                if (output.FailureStage == null) { try { output.Drain(ref captured); } catch { } }
                                if (error.FailureStage == null) { try { error.Drain(ref captured); } catch { } }
                                if (HasExited(process) && Query(job).ActiveProcesses == 0 && output.Eof && error.Eof) break;
                                Thread.Sleep(25);
                            }
                            uint exitCode;
                            Check(GetExitCodeProcess(process, out exitCode));
                            Accounting accounting = Query(job);
                            output.Dispose(); error.Dispose();
                            if (contextAcquired)
                            {
                                try
                                {
                                    contextExitObserved = HasExited(context);
                                    if (contextExitObserved == true)
                                    {
                                        uint contextCode;
                                        Check(GetExitCodeProcess(context, out contextCode));
                                        contextObservedExitCode = contextCode;
                                    }
                                }
                                catch (Exception caught)
                                {
                                    if (failure == null) failure = caught;
                                }
                            }
                            clean = HasExited(process) && accounting.ActiveProcesses == 0 && output.Eof && error.Eof &&
                                output.FailureStage == null && error.FailureStage == null && exitCode == 0 &&
                                contextOwned && contextExitObserved == true;
                            journal.Write("entry-final", "ready", ready, "wslExited", HasExited(process), "wslExitCode", exitCode,
                                "activeProcesses", accounting.ActiveProcesses, "totalProcesses", accounting.TotalProcesses,
                                "stdoutEof", output.Eof, "stderrEof", error.Eof, "capturedBytes", captured,
                                "contextHandleAcquired", contextAcquired, "contextCreationMatched", contextCreationMatched,
                                "contextOwnershipValidated", contextOwned, "contextReleaseRequested", contextReleaseRequested,
                                "contextExited", contextExitObserved, "contextExitCode", contextObservedExitCode,
                                "rejectionReason", rejectionReason,
                                "clean", clean, "failureStage", failure == null ? null : stage,
                                "failureType", failure == null ? null : failure.GetType().Name);
                        }
                        catch (Exception caught) { if (failure == null) failure = caught; }
                    }
                    try
                    {
                        journal.DeadlineMilliseconds = TotalMilliseconds;
                        journal.Write("entry-ownership-final", "ready", ready,
                            "contextHandleAcquired", contextAcquired, "contextCreationMatched", contextCreationMatched,
                            "contextOwnershipValidated", contextOwned, "contextReleaseRequested", contextReleaseRequested,
                            "contextExited", contextExitObserved, "contextExitCode", contextObservedExitCode,
                            "rejectionReason", rejectionReason,
                            "failureType", failure == null ? null : failure.GetType().Name);
                    }
                    catch (Exception caught) { if (failure == null) failure = caught; }
                    if (thread != null) thread.Dispose();
                    if (context != null) context.Dispose();
                    if (process != null) process.Dispose();
                    if (job != null) job.Dispose();
                    if (output != null) output.Dispose();
                    if (error != null) error.Dispose();
                }
            }
            return ready && clean && failure == null && Elapsed < TotalMilliseconds ? 0 : 1;
        }
    }

    private static string JobName(string nonce) { return @"Local\azureauth-elevation-108-" + nonce; }
    private static string EventName(string nonce) { return @"Local\azureauth-elevation-context-108-" + nonce; }
    private static string Scope(string nonce) { return "azureauth-elevation-108-" + nonce + ".scope"; }
    private static bool Elevated(IntPtr process)
    {
        SafeFileHandle token;
        Check(OpenProcessToken(process, 8, out token));
        using (token)
        {
            uint value, returned;
            Check(GetTokenInformation(token, 20, out value, 4, out returned));
            if (returned != 4) throw new InvalidOperationException("Token result size");
            return value != 0;
        }
    }
    private static string ProcessImage(SafeFileHandle process)
    {
        var text = new StringBuilder(32768);
        uint size = 32768;
        Check(QueryFullProcessImageName(process, 0, text, ref size));
        return text.ToString();
    }
    private sealed class GuardFailure : Exception
    {
        public readonly int Reason;
        public GuardFailure(int reason) { Reason = reason; }
    }
    private static int AdmitImage(SafeFileHandle process, string expected, FileStream pinned)
    {
        string actual = ProcessImage(process);
        if (actual == expected) return 0;
        if (!String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) return 124;
        if (!AsciiCaseVariant(actual, expected)) return 126;
        AssertDirect(actual);
        using (FileStream alternate = new FileStream(actual, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (alternate.Length > 2097152) throw new InvalidOperationException("Input size");
            if (!SameFileIdentity(pinned, alternate)) return 129;
        }
        return 0;
    }
    private static bool AsciiCaseVariant(string actual, string expected)
    {
        if (actual.Length != expected.Length) return false;
        for (int index = 0; index < actual.Length; index++)
        {
            char left = actual[index], right = expected[index];
            if (left > 127 || right > 127) return false;
            if (left >= 'A' && left <= 'Z') left = (char)(left + ('a' - 'A'));
            if (right >= 'A' && right <= 'Z') right = (char)(right + ('a' - 'A'));
            if (left != right) return false;
        }
        return true;
    }
    private static bool SameFileIdentity(FileStream pinned, FileStream actual)
    {
        FileIdentity left, right;
        Check(GetFileInformationByHandleEx(pinned.SafeFileHandle, 18, out left, 24));
        Check(GetFileInformationByHandleEx(actual.SafeFileHandle, 18, out right, 24));
        return ValidFileIdentity(left) && ValidFileIdentity(right) &&
            left.VolumeSerialNumber == right.VolumeSerialNumber &&
            left.FileIdLow == right.FileIdLow && left.FileIdHigh == right.FileIdHigh;
    }
    private static bool ValidFileIdentity(FileIdentity value)
    {
        // Unsupported or nonunique file-ID sentinels cannot establish identity.
        return (value.FileIdLow != 0 || value.FileIdHigh != 0) &&
            (value.FileIdLow != ulong.MaxValue || value.FileIdHigh != ulong.MaxValue);
    }
    private static void WaitForMarker(string root, string leaf, string nonce, long deadline,
        SafeFileHandle process, Pipe output, Pipe error, ref int captured)
    {
        while (!Directory.Exists(Path.Combine(root, leaf)))
        {
            if (Elapsed >= deadline || HasExited(process)) throw new TimeoutException("Entry startup");
            output.Drain(ref captured); error.Drain(ref captured); Thread.Sleep(100);
        }
        AssertDirect(Path.Combine(root, leaf));
    }
    private static bool StopRequested(string root, string nonce)
    {
        string path = Path.Combine(root, "stop");
        if (!Directory.Exists(path))
        {
            if (File.Exists(path)) throw new InvalidOperationException("Stop marker type");
            return false;
        }
        AssertDirect(path);
        return true;
    }
    private static void RequestStop(string root, string nonce)
    {
        Directory.CreateDirectory(Path.Combine(root, "stop"));
        AssertDirect(Path.Combine(root, "stop"));
    }
    private static void CreateText(string path, string text)
    {
        AssertDirect(Path.GetDirectoryName(path));
        using (FileStream file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            byte[] raw = Encoding.ASCII.GetBytes(text);
            file.Write(raw, 0, raw.Length); file.Flush(true);
        }
    }
    private static FileStream OpenRead(string path, int maximum)
    {
        AssertDirect(path);
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length > maximum) { file.Dispose(); throw new InvalidOperationException("Input size"); }
        return file;
    }
    private static string ReadText(FileStream file)
    {
        file.Position = 0;
        byte[] raw = new byte[checked((int)file.Length)];
        int position = 0;
        while (position < raw.Length)
        {
            int count = file.Read(raw, position, raw.Length - position);
            if (count == 0) throw new InvalidOperationException("Short text");
            position += count;
        }
        if (file.ReadByte() != -1) throw new InvalidOperationException("Text grew");
        foreach (byte item in raw) if (item > 127 || item == 0 || item == 13) throw new InvalidOperationException("Text encoding");
        return Encoding.ASCII.GetString(raw);
    }
    private static ProcessInformation StartWsl(SafeFileHandle job, Pipe output, Pipe error,
        string root, string command)
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
                // Preserve the designated owner's ordinary Windows/WSL baseline.
                var startup = new StartupInformation();
                startup.Size = Marshal.SizeOf(startup);
                startup.Flags = 0x100; // STARTF_USESTDHANDLES
                startup.Input = input.DangerousGetHandle();
                startup.Output = output.Writer.DangerousGetHandle();
                startup.Error = error.Writer.DangerousGetHandle();
                startup.Attributes = attributes;
                ProcessInformation child;
                // SUSPENDED | UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | NO_WINDOW.
                Check(CreateProcess(Wsl, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true,
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

    private static bool IsHash(string value) { return Regex.IsMatch(value, @"\A[0-9a-f]{64}\z"); }
    private static void Check(bool value) { if (!value) throw new Win32Exception(); }
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
            text.Append(",\"elapsedMilliseconds\":").Append(Elapsed.ToString(CultureInfo.InvariantCulture));
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
            if (DeadlineMilliseconds.HasValue && Elapsed >= DeadlineMilliseconds.Value)
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

    // FILE_ID_INFO: one 64-bit volume number followed by all 128 file-ID bits.
    [StructLayout(LayoutKind.Sequential)] private struct FileIdentity
    { public ulong VolumeSerialNumber, FileIdLow, FileIdHigh; }
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
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct ShellInformation
    {
        public int Size; public uint Mask; public IntPtr Window;
        public string Verb, File, Parameters, Directory;
        public int Show; public IntPtr Instance, IdList; public string Class;
        public IntPtr ClassKey; public uint HotKey; public IntPtr IconOrMonitor, Process;
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ShellExecuteEx(ref ShellInformation info);
    [DllImport("ole32.dll")] private static extern int CoInitializeEx(IntPtr reserved, uint flags);
    [DllImport("ole32.dll")] private static extern void CoUninitialize();
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
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, out FileIdentity identity, uint size);
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
    [DllImport("kernel32.dll")] private static extern ulong GetTickCount64();
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeFileHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeFileHandle token, int kind, out uint value, uint size, out uint returned);
}
