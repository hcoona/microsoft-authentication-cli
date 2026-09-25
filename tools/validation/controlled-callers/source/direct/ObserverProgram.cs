#nullable enable
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace ConfidentialWsl;

internal static class ObserverProgram
{
    private static readonly bool ExecutionAdmitted = false;
    private static bool frameAttempted;
    internal static long Now => Stopwatch.GetTimestamp();
    internal static long Add(long start, int milliseconds) => checked(start + Stopwatch.Frequency * milliseconds / 1000);
    internal static int Remaining(long deadline, int cap) => checked((int)Math.Max(0,
        Math.Min(cap, (deadline - Now) * 1000 / Stopwatch.Frequency)));
    internal static void Before(long deadline) { if (Now >= deadline) throw new SafeFailure(Fault.Deadline); }
    internal static int Milliseconds(long start, long end) => checked((int)
        (((end - start) * 1000 + Stopwatch.Frequency - 1) / Stopwatch.Frequency));

    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted) return 125;
        long entry = Now; bool worker = args.Length > 0 && args[0] == "--worker";
        try
        {
            PrivateExpectation.Check(OperatingSystem.IsWindows() && IntPtr.Size == 8 && Stopwatch.IsHighResolution &&
                args.Length is 5 or 6 or 7 && Enum.TryParse(args[1], false, out Slot slot) && slot.ToString() == args[1] &&
                Regex.IsMatch(args[2], "\\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\\z"));
            slot = Enum.Parse<Slot>(args[1], false);
            bool fixture=slot==Slot.D0 || DirectRoles.Fixture(slot);
            PrivateExpectation.Check(worker ? args.Length == (fixture?7:6) : args.Length == 5 && args[0] == "--supervisor");
            long workEnd=Add(entry,145000);
            if(worker)PrivateExpectation.Check(long.TryParse(args[5],NumberStyles.None,CultureInfo.InvariantCulture,out workEnd) &&
                workEnd>Now && workEnd<=Add(entry,145000));
            AdmissionCatalog.Configure(args[3],args[4],slot,args[2],worker,workEnd,worker && fixture?args[6]:null);
            PublicPlan plan = AdmissionCatalog.LoadPublicPlan(slot, args[2]); AdmissionCatalog.Validate(plan);
            using IDisposable lease = AdmissionCatalog.HoldAcceptedInputs(plan, slot, args[2], worker);
            if (!worker) return Supervise(plan, slot, args[2], entry);
            Observation result = slot == Slot.D0 ? EtwObserver.RunCalibration(plan, args[2], workEnd) :
                EtwObserver.Run(plan, slot, args[2], workEnd);
            WriteFrame(result.Encode(slot)); return result.Passed ? 0 : 1;
        }
        catch (Exception caught)
        {
            if (worker && !frameAttempted)
                try { WriteFrame([79, 87, 70, 49, (byte)(caught is SafeFailure safe ? safe.Fault : Fault.Native)]); } catch { }
            return 1; // No exception text/class, argv, environment, diagnostics or raw output.
        }
        finally { try { AdmissionCatalog.Close(); } catch { } }
    }
    private static void WriteFrame(byte[] frame)
    { frameAttempted = true; using var output = Console.OpenStandardOutput(); output.Write(frame); output.Flush(); }

    private static int Supervise(PublicPlan plan, Slot slot, string nonce, long entry)
    {
        long workEnd = Add(entry, 145000), terminalEnd = Add(workEnd, 10000);
        SafeFileHandle? job = null; Child? worker = null;
        MemoryPipe? output = null, error = null; InputPipe? input = null;
        bool complete = false, jobZero = false, stop = false, stopSucceeded = false;
        uint total = 0, exit = uint.MaxValue; Fault fault = Fault.None; Observation? result = null;
        uint expectedTotal = slot == Slot.D0 ? 3u : 1u;
        try
        {
            try
            {
                Before(workEnd);
                // Real product remains outside this Job. D0 alone admits two synthetic children.
                job = Native.NewJob(JobName(slot, nonce), slot == Slot.D0 ? 2 : 0);
                output = new MemoryPipe(40); error = new MemoryPipe(1); input = new InputPipe(false);
                worker = Native.StartSuspended(plan.ObserverImage,
                    AdmissionCatalog.WorkerArguments(slot,nonce,workEnd),
                    plan.WorkingDirectory, input, output, error, job);
                Before(workEnd); worker.ResumeOnce();
                for (int polls = 0; polls < 15500; polls++)
                {
                    Before(workEnd);
                    if (output.Failed || error.Failed) throw new SafeFailure(Fault.Capture);
                    Native.Accounting count = Native.Query(job); jobZero = count.ActiveProcesses == 0; total = count.TotalProcesses;
                    PrivateExpectation.Check(total <= expectedTotal);
                    if (worker.Exited() && jobZero && output.Done && output.Eof && error.Done && error.Eof)
                    { complete = true; exit = worker.ExitCode(); break; }
                    Thread.Sleep(10);
                }
                Before(workEnd); PrivateExpectation.Check(complete && total >= 1 && total <= expectedTotal && error.Bytes.Length == 0);
                ReadOnlySpan<byte> frame = output.Bytes.Span;
                if (frame.Length == 5 && frame[..4].SequenceEqual("OWF1"u8))
                { PrivateExpectation.Check(frame[4] > 0 && frame[4] <= (byte)Fault.Lifetime); fault = (Fault)frame[4]; }
                else { result = Observation.Decode(frame, slot); fault = result.FailureKind; }
                terminalEnd = Math.Min(terminalEnd, Add(Now, 10000));
            }
            catch (Exception caught)
            {
                fault = caught is SafeFailure safe ? safe.Fault : Fault.Native;
                terminalEnd = Math.Min(terminalEnd, Add(Now, 10000));
                if (!complete && job is not null)
                {
                    stop = true;
                    try { stopSucceeded = Native.TerminateJobObject(job, 1); } catch { }
                    for (int polls = 0; polls < 1000 && Now < terminalEnd; polls++)
                    {
                        try
                        {
                            Native.Accounting count = Native.Query(job); jobZero = count.ActiveProcesses == 0; total = count.TotalProcesses;
                            if (worker is not null && worker.Exited() && jobZero &&
                                output is { Done: true, Eof: true, Failed: false } && error is { Done: true, Eof: true, Failed: false })
                            { complete = true; exit = worker.ExitCode(); break; }
                        }
                        catch { break; }
                        Thread.Sleep(10);
                    }
                }
            }
            if (!complete || !jobZero || Now >= terminalEnd) return 1;
            bool passed = !stop && exit == 0 && fault == Fault.None && result is { Passed: true } && total == expectedTotal &&
                (!DirectRoles.Close(slot) || result.AnchorAckPublished && result.EndByAnchorDeadline) &&
                result.Exit == plan.ExpectedExit && result.Callbacks <= 65536 &&
                result.DurationMs >= 0 && result.DurationMs <= plan.ProductTimeoutSeconds * 1000 + 1000;
            var record = PublicRecords.Identity(plan, slot, nonce, "observer-final");
            record["passed"] = passed; record["workerExited"] = true; record["observerJobZero"] = true;
            record["observerJobTotal"] = total; record["observerStopAttempted"] = stop;
            record["observerStopSucceeded"] = stopSucceeded; record["fault"] = fault.ToString();
            record["nativeEvidence"] = result is { NativeComplete: true } ?
                slot == Slot.D0 ? "calibration-creation-handles" : "matched-native-events" : "unknown";
            record["productInObserverJob"] = slot == Slot.D0; record["productLifetimeKnown"] = result?.NativeComplete ?? false;
            record["traceStopped"] = result?.TraceStopped ?? false; record["traceDrained"] = result?.TraceDrained ?? false;
            record["traceZeroLoss"] = result?.ZeroLoss ?? false; record["targetStopAttempted"] = result?.TargetStop ?? false;
            record["retainedHandleExited"] = result?.HandleExited ?? false;
            record["callbacks"] = result?.Callbacks ?? 0; record["eventsLost"] = result?.EventsLost ?? -1;
            record["logBuffersLost"] = result?.LogLost ?? -1; record["realTimeBuffersLost"] = result?.RealTimeLost ?? -1;
            record["nativeExit"] = result?.Exit ?? -1; record["nativeDurationMs"] = result?.DurationMs ?? -1;
            record["anchorAckPublished"] = result?.AnchorAckPublished ?? false;
            record["endByAnchorDeadline"] = result?.EndByAnchorDeadline ?? false;
            record["anchorToEndUpperBoundMs"] = result?.AnchorUpperMs ?? -1;
            record["scenarioAccepted"] = false;
            // D0 aggregates both original creation-handle/START/END/EOF joins. It
            // supplies calibration evidence only, never real-product acceptance.
            PublicRecords.Publish(plan, "observer-final.json", record);
            Before(terminalEnd); return passed ? 0 : 1;
        }
        finally { worker?.Dispose(); job?.Dispose(); input?.Dispose(); output?.Dispose(); error?.Dispose(); }
    }
    internal static string JobName(Slot slot, string nonce) => "Local\\azureauth-confidential-wsl-108-" + slot + "-" + nonce;
}

internal sealed class Observation
{
    internal bool TraceStopped, TraceDrained, ZeroLoss, StartMatched, EndMatched, HandleRetained,
        HandleExited, TargetStop, NativeComplete, TimingValid, ExpectedExit, AnchorAckPublished, EndByAnchorDeadline;
    internal int Exit = -1, Callbacks, EventsLost = -1, LogLost = -1, RealTimeLost = -1, DurationMs = -1;
    internal int AnchorUpperMs = -1;
    internal Fault FailureKind;
    internal bool Passed => FailureKind == Fault.None && TraceStopped && TraceDrained && ZeroLoss &&
        StartMatched && EndMatched && NativeComplete && TimingValid && ExpectedExit && !TargetStop &&
        (!HandleRetained || HandleExited);
    internal byte[] Encode(Slot slot)
    {
        byte[] frame = new byte[40];
        if (slot == Slot.D0) "OWK1"u8.CopyTo(frame); else "OWS2"u8.CopyTo(frame);
        bool[] bits = [TraceStopped, TraceDrained, ZeroLoss, StartMatched, EndMatched, HandleRetained,
            HandleExited, TargetStop, NativeComplete, TimingValid, ExpectedExit, AnchorAckPublished, EndByAnchorDeadline];
        uint flags = 0; for (int i = 0; i < bits.Length; i++) if (bits[i]) flags |= 1u << i;
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4), flags);
        int[] values = [Exit, Callbacks, EventsLost, LogLost, RealTimeLost, DurationMs, (int)FailureKind, AnchorUpperMs];
        for (int i = 0; i < values.Length; i++) BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(8 + 4 * i), values[i]);
        return frame;
    }
    internal static Observation Decode(ReadOnlySpan<byte> frame, Slot slot)
    {
        PrivateExpectation.Check(frame.Length == 40 && (slot == Slot.D0 ?
            frame[..4].SequenceEqual("OWK1"u8) : frame[..4].SequenceEqual("OWS2"u8)));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(frame[4..]);
        PrivateExpectation.Check((flags & ~8191u) == 0);
        var result = new Observation { TraceStopped = (flags & 1) != 0, TraceDrained = (flags & 2) != 0,
            ZeroLoss = (flags & 4) != 0, StartMatched = (flags & 8) != 0, EndMatched = (flags & 16) != 0,
            HandleRetained = (flags & 32) != 0, HandleExited = (flags & 64) != 0, TargetStop = (flags & 128) != 0,
            NativeComplete = (flags & 256) != 0, TimingValid = (flags & 512) != 0, ExpectedExit = (flags & 1024) != 0,
            Exit = BinaryPrimitives.ReadInt32LittleEndian(frame[8..]), Callbacks = BinaryPrimitives.ReadInt32LittleEndian(frame[12..]),
            EventsLost = BinaryPrimitives.ReadInt32LittleEndian(frame[16..]), LogLost = BinaryPrimitives.ReadInt32LittleEndian(frame[20..]),
            RealTimeLost = BinaryPrimitives.ReadInt32LittleEndian(frame[24..]), DurationMs = BinaryPrimitives.ReadInt32LittleEndian(frame[28..]),
            FailureKind = (Fault)BinaryPrimitives.ReadInt32LittleEndian(frame[32..]),
            AnchorAckPublished = (flags & 2048) != 0, EndByAnchorDeadline = (flags & 4096) != 0,
            AnchorUpperMs = BinaryPrimitives.ReadInt32LittleEndian(frame[36..]) };
        PrivateExpectation.Check(result.Callbacks is >= 0 and <= 65537 && result.EventsLost >= -1 && result.LogLost >= -1 &&
            result.RealTimeLost >= -1 && result.DurationMs is >= -1 and <= 155000 && Enum.IsDefined(result.FailureKind));
        PrivateExpectation.Check(!result.ZeroLoss || result.EventsLost == 0 && result.LogLost == 0 && result.RealTimeLost == 0);
        PrivateExpectation.Check(!result.NativeComplete || result.StartMatched && result.EndMatched && result.TraceStopped &&
            result.TraceDrained && result.ZeroLoss && (!result.HandleRetained || result.HandleExited));
        PrivateExpectation.Check(!result.HandleExited || result.HandleRetained);
        PrivateExpectation.Check(!result.TraceDrained || result.TraceStopped);
        PrivateExpectation.Check(!result.ExpectedExit || result.Exit is 0 or 1);
        PrivateExpectation.Check(!result.EndByAnchorDeadline || result.AnchorAckPublished &&
            result.NativeComplete && result.TimingValid && result.ExpectedExit && !result.TargetStop &&
            result.FailureKind == Fault.None && result.AnchorUpperMs is >= 1 and <= 1000);
        PrivateExpectation.Check(result.EndByAnchorDeadline || result.AnchorUpperMs == -1);
        PrivateExpectation.Check(DirectRoles.Close(slot) || !result.AnchorAckPublished &&
            !result.EndByAnchorDeadline && result.AnchorUpperMs == -1);
        return result;
    }
}
