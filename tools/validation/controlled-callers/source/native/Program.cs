#nullable enable
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace ConfidentialNativeCaller;

internal static class Program
{
    private static readonly bool ExecutionAdmitted = false;
    private static bool workerOutputAttempted;
    // Actual supervisors expose only a fixed public status, never exception or provider text.
    private static bool actualSupervisor;
    private static byte actualStage;
    private static int actualInputOrdinal = -1;
    private static ushort actualFlags;
    private static Fault? actualFault;
    internal static void ActualAt(byte stage, int inputOrdinal = -1)
    {
        if (!actualSupervisor || actualFault is not null) return;
        actualStage = stage; actualInputOrdinal = inputOrdinal;
    }
    internal static void ActualFlag(ushort flag) { if (actualSupervisor) actualFlags |= flag; }
    internal static void ActualCapture(Exception caught)
    {
        if (actualSupervisor) actualFault ??= caught is SafeFailure safe ? safe.Fault : Fault.Native;
    }
    internal static byte[] ActualStatus(byte stage, byte fault, ushort flags, int inputOrdinal, int exitCode)
    {
        PrivateRequest.Require(stage is >= 1 and <= 17 && fault <= 7 && flags <= 1023 &&
            inputOrdinal is >= -1 and <= 225 && exitCode is 0 or 1);
        byte[] bytes = new byte[16];
        bytes[0] = 78; bytes[1] = 65; bytes[2] = 83; bytes[3] = 49; // NAS1
        bytes[4] = stage; bytes[5] = fault;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(6, 2), flags);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), inputOrdinal);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12, 4), exitCode);
        return bytes;
    }
    private const int WorkMilliseconds = 135000, TerminalMilliseconds = 10000;
    private static long Now => Stopwatch.GetTimestamp();
    private static long Add(long start, int milliseconds) => CallerRules.Add(start, milliseconds, Stopwatch.Frequency);
    private static int Elapsed(long start) => checked((int)((Now - start) * 1000 / Stopwatch.Frequency));
    private static int CeilingMilliseconds(long start, long end) =>
        checked((int)(((end - start) * 1000 + Stopwatch.Frequency - 1) / Stopwatch.Frequency));
    private static void Before(long deadline) => CallerRules.Before(Now, deadline);

    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted) return 125; // No loading, file access, private reference or native call behind this guard.
        long entry = Now;
        bool fixture = args.Length > 0 && args[0] is "--fixture-worker" or "--fixture-supervisor";
        bool worker = args.Length > 0 && args[0] is "--worker" or "--fixture-worker";
        actualSupervisor = args.Length > 0 && args[0] == "--supervisor";
        int actualExitCode = 1;
        long diagnosticEnd=(fixture && !worker) || actualSupervisor?Add(entry,WorkMilliseconds+TerminalMilliseconds):0;
        if(fixture && !worker && args.Length==7 && long.TryParse(args[6],NumberStyles.None,CultureInfo.InvariantCulture,out long bound))
            diagnosticEnd=Math.Min(diagnosticEnd,bound);
        if(actualSupervisor && args.Length==8 && long.TryParse(args[7],NumberStyles.None,CultureInfo.InvariantCulture,out long actualBound))
            diagnosticEnd=Math.Min(diagnosticEnd,actualBound);
        try
        {
            if (fixture) return FixturePins.RunRole(args, entry, worker);
            actualExitCode = AdmissionCatalog.RunRole(args, entry, worker);
            return actualExitCode;
        }
        catch (Exception caught)
        {
            if(fixture && !worker)FixtureDiagnostics.Capture(caught);
            ActualCapture(caught);
            // A fixed enum preserves only the first safe cause. Never format the exception.
            if (worker && !workerOutputAttempted)
                try { WriteWorkerFrame([78, 67, 70, 49, (byte)(caught is SafeFailure safe ? safe.Fault : Fault.Native)]); } catch { }
            return 1;
        }
        finally
        {
            // Only synthetic supervisors report a bounded cause to the driver's existing pipe.
            // Failure to report cannot change exit status, trigger a retry, or renew a deadline.
            if(fixture && !worker && FixtureDiagnostics.First is FixtureFailure failure)
                try { Before(diagnosticEnd);Console.OpenStandardError().Write(failure.Encode()); } catch { }
            if(actualSupervisor)
                try
                {
                    Before(diagnosticEnd);
                    Console.OpenStandardError().Write(ActualStatus(actualStage,
                        actualFault is Fault fault ? (byte)fault : (byte)7, actualFlags, actualInputOrdinal, actualExitCode));
                }
                catch { } // Missing status is unavailable; reporting cannot renew a deadline or retry.
        }
    }

    internal static void ValidatePublicPlan(PublicPlan plan)
    {
        foreach (string hash in new[] { plan.ProductSha256, plan.CallerSha256, plan.ProtocolSha256 })
            PrivateRequest.Require(Regex.IsMatch(hash, "\\A[0-9a-f]{64}\\z"));
        foreach (string path in new[] { plan.SelfImage, plan.ProductImage, plan.WorkingDirectory, plan.ReceiptDirectory })
            PrivateRequest.Require(path.Length is >= 3 and <= 32767 && char.IsAsciiLetter(path[0]) &&
                path[1] == ':' && path[2] == '\\' && !path.Any(char.IsControl));
        // ActualAdmission owns exact public bytes, native identities and held inputs.
        // Syntactic validation alone is not artifact or pre-loader acceptance.
    }

    internal static int Supervise(PublicPlan plan, Group group, string nonce, long entry, bool fixture, long? fixtureFinalEnd = null, long? admittedWorkEnd = null, long? admittedFinalEnd = null)
    {
        long workEnd = Add(entry, WorkMilliseconds), finalEnd = Add(workEnd, TerminalMilliseconds);
        if (fixture)
        {
            PrivateRequest.Require(fixtureFinalEnd is long && fixtureFinalEnd > entry);
            finalEnd = Math.Min(finalEnd, fixtureFinalEnd!.Value);
            workEnd = Math.Min(workEnd, checked(finalEnd - Stopwatch.Frequency * TerminalMilliseconds / 1000));
        }
        if (!fixture)
        {
            PrivateRequest.Require(admittedWorkEnd is long && admittedFinalEnd is long);
            workEnd = Math.Min(workEnd, admittedWorkEnd!.Value);
            finalEnd = Math.Min(finalEnd, admittedFinalEnd!.Value);
            PrivateRequest.Require(workEnd > Now && finalEnd > workEnd);
        }
        string[] slots = AdmissionCatalog.Slots(group);
        ActualAt(10);
        if(fixture)FixtureDiagnostics.At(FixtureStage.Reservation);
        foreach (string slot in slots) Receipt(plan, slot, nonce, true, null, false, false, false, false, false, entry, workEnd);
        SafeFileHandle? job = null;
        Child? worker = null;
        MemoryPipe? output = null, error = null;
        InputPipe? input = null;
        IDisposable? workerIdentity = null;
        bool complete = false, jobZero = false, stopAttempted = false, stopSucceeded = false, passed = false;
        uint? exit = null;
        uint total = 0;
        SafeResult[]? results = null;
        Fault? firstFault = null;
        long terminalEnd = finalEnd;
        try
        {
            try
            {
                Before(workEnd);
                if(fixture)FixtureDiagnostics.At(FixtureStage.CreateWorker);
                ActualAt(11);
                job = Native.NewJob("Local\\azureauth-confidential-108-" + group + "-" + nonce, slots.Length);
                ActualFlag(1);
                output = new MemoryPipe(32); error = new MemoryPipe(1); input = new InputPipe(false);
                using (CurrentUserEnvironment? environment = fixture ? null : CurrentUserEnvironment.Create(workEnd))
                {
                    if(fixture)FixtureDiagnostics.At(FixtureStage.CreateWorker);
                    Before(workEnd);
                    ActualAt(12);
                    worker = Native.StartSuspended(plan.SelfImage,
                        fixture ? FixturePins.RoleArguments(group, "worker", workEnd) :
                        AdmissionCatalog.WorkerArguments(group, nonce, workEnd, finalEnd),
                        plan.WorkingDirectory, input, output, error, job, environment?.Block ?? IntPtr.Zero);
                    ActualFlag(2);
                }
                ActualAt(13);
                if (fixture){FixtureDiagnostics.At(FixtureStage.BindWorker);workerIdentity = FixturePins.BindCreated(group, "worker", worker, workEnd);}
                else workerIdentity = AdmissionCatalog.BindWorker(group, nonce, worker, workEnd, finalEnd);
                if(fixture)FixtureDiagnostics.At(FixtureStage.ResumeWorker);
                ActualAt(14);
                Before(workEnd); worker.ResumeOnce(); ActualFlag(4);
                if(fixture)FixtureDiagnostics.At(FixtureStage.WaitWorker);
                ActualAt(15);
                while (true)
                {
                    Before(workEnd);
                    if (output.Failed || error.Failed) throw new SafeFailure(Fault.Capture);
                    Native.Accounting count = Native.Query(job);
                    jobZero = count.ActiveProcesses == 0; total = count.TotalProcesses;
                    if (CallerRules.SupervisorComplete(worker.Exited(), jobZero, output.Done, output.Eof, error.Done, error.Eof))
                    { exit = worker.ExitCode(); complete = true; ActualFlag(8 | 16 | 32); break; }
                    Thread.Sleep(10);
                }
                Before(workEnd);
                if(fixture)FixtureDiagnostics.At(FixtureStage.ValidateWorker);
                ActualAt(16);
                terminalEnd = Math.Min(terminalEnd, Add(Now, TerminalMilliseconds));
                FrameDecision decision = CallerRules.DecideFrame(output.Bytes.Span, slots.Length, total, exit!.Value, error.Bytes.Length);
                results = decision.Results; firstFault = decision.FirstFault; passed = decision.Passed;
            }
            catch (Exception caught)
            {
                if(fixture)FixtureDiagnostics.Capture(caught);
                ActualCapture(caught);
                passed = false;
                firstFault ??= caught is SafeFailure safe ? safe.Fault : Fault.Native;
                terminalEnd = Math.Min(terminalEnd, Add(Now, TerminalMilliseconds));
                // Exactly one explicit stop on our newly created Job. No worker-side kill,
                // reopen-by-PID, shared broker/session adoption, or restart of this window.
                if (!complete && job is not null)
                {
                    stopAttempted = true;
                    ActualFlag(64);
                    try { stopSucceeded = Native.TerminateJobObject(job, 1); } catch { }
                    if (stopSucceeded) ActualFlag(128);
                    while (Now < terminalEnd)
                    {
                        try
                        {
                            Native.Accounting count = Native.Query(job);
                            jobZero = count.ActiveProcesses == 0; total = count.TotalProcesses;
                            bool workerExit = worker is not null && worker.Exited();
                            bool streams = output is { Done: true, Eof: true, Failed: false } &&
                                error is { Done: true, Eof: true, Failed: false };
                            if (CallerRules.SupervisorComplete(workerExit, jobZero, streams, streams, streams, streams))
                            { exit = worker!.ExitCode(); complete = true; ActualFlag(8 | 16 | 32); break; }
                        }
                        catch { break; }
                        Thread.Sleep(10);
                    }
                }
            }
            // Missing closure or safe EOF leaves the reservation open. Last-close Job
            // termination is only a fallback; it cannot manufacture a terminal witness.
            if (!complete || !jobZero || Now >= terminalEnd) return 1;
            if(fixture)FixtureDiagnostics.At(FixtureStage.TerminalReceipt);
            ActualAt(17);
            for (int i = 0; i < slots.Length; i++)
                Receipt(plan, slots[i], nonce, false, results?[i], CallerRules.TerminalMayPass(passed, stopAttempted),
                    true, true, stopAttempted, stopSucceeded, entry, terminalEnd, firstFault);
            return CallerRules.TerminalMayPass(passed, stopAttempted) ? 0 : 1;
        }
        catch (Exception caught) { ActualCapture(caught); throw; }
        finally
        {
            worker?.Dispose(); job?.Dispose(); input?.Dispose(); output?.Dispose(); error?.Dispose(); workerIdentity?.Dispose();
            ActualFlag(256); // Handle disposal is separate from observed worker/Job/stream completion.
        }
    }

    private sealed class Live : IDisposable
    {
        internal readonly PrivateRequest Request;
        internal readonly long Began, Deadline;
        internal readonly MemoryPipe Output = null!, Error = null!;
        internal readonly InputPipe Input = null!;
        internal Child? Child;
        internal SafeResult? Result;
        internal bool ClosedAfterLiveSample;
        internal long? WriterCloseBegan, CancellationEnd, ExitObserved;
        internal long EffectiveDeadline => CallerRules.EffectiveDeadline(Deadline, CancellationEnd);
        internal Live(PrivateRequest request, long began, long deadline)
        {
            Request = request; Began = began; Deadline = deadline;
            try { Output = new MemoryPipe(1048576); Error = new MemoryPipe(8192); Input = new InputPipe(request.LifetimePipe); }
            catch { Dispose(); throw; }
        }
        public void Dispose() { Child?.Dispose(); Input?.Dispose(); Output?.Dispose(); Error?.Dispose(); }
    }

    internal static int Work(PublicPlan plan, Group group, long originalWorkEnd, bool fixture)
    {
        PrivateRequest[] requests = fixture ? FixtureAdmission.Requests(group) : AdmissionCatalog.LoadPrivateRequests(group);
        PrivateRequest.Require(requests.Length == AdmissionCatalog.Slots(group).Length);
        foreach (PrivateRequest request in requests) request.Validate();
        if (group == Group.R5Pair)
        {
            PrivateRequest a = requests[0], b = requests[1];
            PrivateRequest.Require(!a.InteractionAllowed && !b.InteractionAllowed &&
                a.ExpectedOutcome == Outcome.Success && b.ExpectedOutcome == Outcome.Success &&
                a.CloseWriterAfterMilliseconds is null && b.CloseWriterAfterMilliseconds is null &&
                a.ProfilePath == b.ProfilePath && string.Equals(a.Email, b.Email, StringComparison.OrdinalIgnoreCase) &&
                a.TenantArgument == b.TenantArgument && a.Scopes.SequenceEqual(b.Scopes, StringComparer.Ordinal));
        }
        var active = new List<Live>(requests.Length);
        try
        {
            foreach (PrivateRequest request in requests)
            {
                long began = Now;
                // Product duration, existing one-second ending allowance, then five
                // seconds for private validation and bounded safe evidence must fit.
                PrivateRequest.Require(Add(began, request.TimeoutSeconds * 1000 + 6000) < originalWorkEnd);
                var live = new Live(request, began, Add(began, request.TimeoutSeconds * 1000 + 1000));
                active.Add(live);
                live.Child = Native.StartSuspended(plan.ProductImage, fixture ? FixtureAdmission.Arguments(group, request) : request.Arguments(), plan.WorkingDirectory,
                    live.Input, live.Output, live.Error, null);
                Before(live.Deadline); live.Child.ResumeOnce();
            }
            // Both products have been resumed before these original-handle samples.
            // If both are unsignaled, their lifetimes overlap at the first sample:
            // a process signaled by exit cannot later become unsignaled again.
            // This witnesses process lifetime only, not simultaneous provider work.
            bool pairOverlap = group == Group.R5Pair && active.All(x => !x.Child!.Exited());
            while (active.Any(x => x.Result is null))
            {
                Before(originalWorkEnd);
                foreach (Live live in active.Where(x => x.Result is null))
                {
                    Before(live.EffectiveDeadline);
                    if (live.Output.Failed || live.Error.Failed) throw new SafeFailure(Fault.Capture);
                    bool exited = live.Child!.Exited();
                    if (exited && live.ExitObserved is null) live.ExitObserved = Now;
                    Before(live.EffectiveDeadline);
                    if (!live.ClosedAfterLiveSample && !exited && live.Request.CloseWriterAfterMilliseconds is int close &&
                        Elapsed(live.Began) >= close)
                    {
                        // Start before the sole close call: any close latency consumes
                        // this nonrenewed second instead of extending the allowance.
                        live.WriterCloseBegan = Now;
                        live.CancellationEnd = CallerRules.CancellationEnd(live.Deadline, live.WriterCloseBegan.Value, Stopwatch.Frequency);
                        live.Input.CloseWriter(); live.ClosedAfterLiveSample = true;
                        Before(live.EffectiveDeadline);
                    }
                    if (!CallerRules.ProductComplete(exited, live.Output.Done, live.Output.Eof, live.Error.Done, live.Error.Eof)) continue;
                    long completionObserved = Now;
                    Before(live.EffectiveDeadline);
                    live.Input.CloseWriter();
                    SafeResult result = ProtocolResult.Validate(live.Output.Bytes, live.Child.ExitCode(), live.Request, live.Output.ReceivedUtc);
                    result.ElapsedMilliseconds = Elapsed(live.Began);
                    result.WriterClosedAfterLiveSample = live.ClosedAfterLiveSample;
                    if (live.WriterCloseBegan is long closed)
                    {
                        result.WriterCloseToExitMilliseconds = CeilingMilliseconds(closed, live.ExitObserved!.Value);
                        result.WriterCloseToCompletionMilliseconds = CeilingMilliseconds(closed, completionObserved);
                    }
                    result.PairProcessOverlapObserved = pairOverlap;
                    result.Passed &= CallerRules.PairPass(group == Group.R5Pair, pairOverlap);
                    result.Passed &= !live.Request.RequireCloseAfterLiveSample || live.ClosedAfterLiveSample;
                    live.Result = result;
                }
                if (active.Any(x => x.Result is null)) Thread.Sleep(10);
            }
            Before(originalWorkEnd);
            SafeResult[] results = active.Select(x => x.Result!).ToArray();
            byte[] safe = Wire.Encode(results);
            WriteWorkerFrame(safe);
            return results.All(x => x.Passed) ? 0 : 1;
        }
        finally { foreach (Live live in active) live.Dispose(); }
    }

    private static void WriteWorkerFrame(byte[] safe)
    {
        CallerRules.WriteFrame(ref workerOutputAttempted, safe, Console.OpenStandardOutput);
    }

    private static void Receipt(PublicPlan plan, string slot, string nonce, bool reservation, SafeResult? result,
        bool passed, bool safeEof, bool jobZero, bool stopAttempted, bool stopSucceeded, long entry, long deadline, Fault? firstFault = null)
    {
        Before(deadline);
        byte[] safe = SafeReceipt.Project(plan, slot, nonce, reservation, result, passed, safeEof, jobZero,
            stopAttempted, stopSucceeded, Elapsed(entry), firstFault);
        string leaf = slot + (reservation ? "-reservation.json" : "-terminal.json");
        SafeReceipt.Persist(safe, () => Before(deadline),
            () => new FileStream(Path.Combine(plan.ReceiptDirectory, leaf), FileMode.CreateNew, FileAccess.Write, FileShare.Read),
            file => ((FileStream)file).Flush(true));
    }

}
