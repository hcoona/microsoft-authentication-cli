// Source-only confidential direct-product witness, adapted from accepted WindowsWslObserver.cs.
// The outside real product is never launched or assigned to a Job here; D0 alone creates two synthetic children.
#nullable disable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
namespace ConfidentialWsl;
internal static class EtwObserver
{
    private static readonly object TargetLock = new object();
    private static readonly List<Target> Targets = new List<Target>();
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly Encoding Utf16 = new UnicodeEncoding(false, false, true);
    private static string Failure, DevicePrefix;
    private static bool ResourceUncertain;
    private static long WorkEnd, TerminalEnd;
    private sealed class FailureException : Exception
    { internal readonly string Code; internal FailureException(string code) { Code = code; } }
    private static void Fail(string code) { Interlocked.CompareExchange(ref Failure, code, null); }
    private static void Require(bool condition, string code) { if (!condition) throw new FailureException(code); }
    private static uint Remaining(int cap) => (uint)ObserverProgram.Remaining(TerminalEnd, cap);

    internal static Observation Run(PublicPlan plan, Slot slot, string nonce, long workEnd)
    {
        WorkEnd = workEnd; TerminalEnd = ObserverProgram.Add(workEnd, 10000);
        long readyEnd = workEnd - Stopwatch.Frequency * 140;
        Trace trace = null; Target target = null; Fault first = Fault.None;
        var result = new Observation();
        try
        {
            ObserverProgram.Before(readyEnd);
            // The supervisor checks the exact Job through the creation handle before
            // resume. Do not open/retain a worker Job handle: that would defeat the
            // supervisor's sole-handle KILL_ON_JOB_CLOSE fallback.
            Require(TraceNative.IsProcessInJob(TraceNative.GetCurrentProcess(), IntPtr.Zero, out bool member) && member,
                "worker-job");
            Require(slot != Slot.D0, "calibration-route");
            if (DirectRoles.Close(slot)) AnchorHandshake.RequireAbsent(plan);
            PrivateExpectation request = AdmissionCatalog.LoadPrivateExpectation(slot);
            target = new Target(plan.ProductImage, request.Command(plan), plan.ExpectedExit,
                plan.ProductTimeoutSeconds, request.TargetedStopPremiseAccepted);
            Targets.Add(target);
            var device = new StringBuilder(1024);
            Require(TraceNative.QueryDosDevice("C:", device, device.Capacity) > 0 &&
                Regex.IsMatch(device.ToString(), @"\A\\Device\\HarddiskVolume[0-9]+\z"), "device-mapping");
            DevicePrefix = device.ToString();
            trace = new Trace("azureauth-confidential-wsl-108-" + slot + "-" + nonce, Guid.ParseExact(nonce, "N"));
            trace.Start(); ObserverProgram.Before(readyEnd);
            target.ReadyQpc = ObserverProgram.Now; target.LaunchEnd = ObserverProgram.Add(target.ReadyQpc, 2000);
            PublicRecords.Publish(plan, "readiness.json", PublicRecords.Identity(plan, slot, nonce, "readiness"));
            bool intent = false;
            for (int polls = 0; polls < 200 && ObserverProgram.Now < target.LaunchEnd; polls++)
            {
                Require(Failure == null, "trace-before-intent");
                if (PublicRecords.StopRequested(plan)) throw new SafeFailure(Fault.Capture);
                if (File.Exists(PublicRecords.PathOf(plan, "intent.json")))
                { PublicRecords.RequireIntent(plan, slot, nonce); intent = true; break; }
                Thread.Sleep(10);
            }
            PrivateExpectation.Check(intent); ObserverProgram.Before(target.LaunchEnd);
            long productEnd = Math.Min(WorkEnd - Stopwatch.Frequency * 17,
                ObserverProgram.Add(target.LaunchEnd, checked(plan.ProductTimeoutSeconds * 1000 + 1000)));
            bool ended = false;
            for (int polls = 0; polls < 12300 && ObserverProgram.Now < productEnd; polls++)
            {
                Require(Failure == null, "trace-active");
                if (PublicRecords.StopRequested(plan)) throw new SafeFailure(Fault.Capture);
                target.TryOpenOriginal();
                lock (TargetLock) ended = target.Ends == 1 && target.ObserveHandle();
                if (ended) break;
                if (DirectRoles.Close(slot) && !target.AnchorSampled && AnchorHandshake.RequestPresent(plan))
                {
                    lock (TargetLock)
                    {
                        Require(Failure == null && target.Starts == 1 && target.Ends == 0 &&
                            !target.AnchorSampled, "anchor-prerequisites");
                        target.AnchorSampled = true;
                        target.AnchorQpc = ObserverProgram.Now;
                        long anchorEnd = checked(target.AnchorQpc + Stopwatch.Frequency);
                        Require(anchorEnd <= productEnd && anchorEnd <= WorkEnd - Stopwatch.Frequency * 17 &&
                            anchorEnd <= ObserverProgram.Add(target.StartQpc,
                                checked(plan.ProductTimeoutSeconds * 1000 + 1000)), "anchor-original-deadline");
                    }
                    // Sample precedes publication. One-shot failure cannot re-anchor.
                    AnchorHandshake.PublishAck(plan);
                    target.AnchorAckPublished = true;
                }
                Thread.Sleep(10);
            }
            if (!ended) throw new SafeFailure(Fault.Deadline);
            ObserverProgram.Before(workEnd);
        }
        catch (Exception caught)
        {
            first = caught is SafeFailure safe ? safe.Fault : Fault.Trace;
            TerminalEnd = Math.Min(TerminalEnd, ObserverProgram.Add(ObserverProgram.Now, 10000));
            try { target?.StopIfNeeded(TerminalEnd); } catch { ResourceUncertain = true; }
        }
        finally
        {
            try
            {
                if (trace != null)
                    trace.StopAndDrain(Math.Min(first == Fault.None ? WorkEnd : TerminalEnd,
                        ObserverProgram.Add(ObserverProgram.Now, 9000)));
            }
            catch { if (first == Fault.None) first = Fault.Trace; ResourceUncertain = true; }
            lock (TargetLock)
            {
                result.TraceStopped = trace != null && trace.Stopped;
                result.TraceDrained = trace != null && trace.Drained;
                result.EventsLost = trace?.EventsLost ?? -1; result.LogLost = trace?.LogBuffersLost ?? -1;
                result.RealTimeLost = trace?.RealTimeBuffersLost ?? -1; result.Callbacks = trace?.Callbacks ?? 0;
                result.ZeroLoss = result.EventsLost == 0 && result.LogLost == 0 && result.RealTimeLost == 0;
                if (target != null)
                {
                    bool handle = false;
                    try { handle = target.ObserveHandle(); } catch { ResourceUncertain = true; }
                    result.StartMatched = target.Starts == 1; result.EndMatched = target.Ends == 1;
                    result.HandleRetained = target.HadHandle; result.HandleExited = target.HandleSignaled;
                    result.TargetStop = target.Forced; result.Exit = target.Ends == 1 ? target.Exit : -1;
                    result.NativeComplete = target.CompleteIdentity && handle && result.TraceStopped &&
                        result.TraceDrained && result.ZeroLoss && !ResourceUncertain && Failure == null;
                    if (target.CompleteIdentity) result.DurationMs = ObserverProgram.Milliseconds(target.StartQpc, target.EndQpc);
                    result.TimingValid = target.CompleteIdentity && target.StartQpc >= target.ReadyQpc &&
                        target.StartQpc <= target.LaunchEnd && target.EndQpc <= ObserverProgram.Add(target.StartQpc,
                            checked(plan.ProductTimeoutSeconds * 1000 + 1000));
                    result.ExpectedExit = target.Ends == 1 && target.Exit == plan.ExpectedExit;
                    result.AnchorAckPublished = target.AnchorAckPublished;
                    if (DirectRoles.Close(slot) && first == Fault.None && result.NativeComplete && result.TimingValid &&
                        result.ExpectedExit && !result.TargetStop && target.AnchorSampled && target.AnchorAckPublished)
                    {
                        try
                        {
                            int upper = AnchorHandshake.ConservativeUpperMilliseconds(target.AnchorQpc, target.EndQpc);
                            if (upper >= 1 && upper <= 1000)
                            { result.EndByAnchorDeadline = true; result.AnchorUpperMs = upper; }
                        }
                        catch { if (first == Fault.None) first = Fault.Lifetime; }
                    }
                    target.Close();
                }
            }
        }
        result.FailureKind = first != Fault.None ? first : Failure != null || ResourceUncertain ? Fault.Trace :
            result.NativeComplete && result.TimingValid && result.ExpectedExit && !result.TargetStop ? Fault.None : Fault.Lifetime;
        return result;
    }

    // Same final observer artifact, same Trace/Decode/Associate path. This mode
    // never loads private expectations and never starts the authentication product.
    internal static Observation RunCalibration(PublicPlan plan, string nonce, long workEnd)
    {
        WorkEnd = workEnd; TerminalEnd = ObserverProgram.Add(workEnd, 10000);
        Trace trace = null; var targets = new List<Target>(); var children = new List<Child>();
        var inputs = new List<InputPipe>(); var outputs = new List<MemoryPipe>(); var errors = new List<MemoryPipe>();
        var result = new Observation(); Fault first = Fault.None; bool gatedWitness = false, fastWitness = false;
        long calibrationEnd = Math.Min(workEnd - Stopwatch.Frequency * 17, ObserverProgram.Add(ObserverProgram.Now, 12000));
        try
        {
            AdmissionCatalog.RequireCalibrationAdmission(plan, nonce);
            Require(plan.ExpectedExit == 0 && plan.ProductTimeoutSeconds == 5 &&
                TraceNative.IsProcessInJob(TraceNative.GetCurrentProcess(), IntPtr.Zero, out bool member) && member,
                "calibration-admission");
            var device = new StringBuilder(1024);
            Require(TraceNative.QueryDosDevice("C:", device, device.Capacity) > 0 &&
                Regex.IsMatch(device.ToString(), @"\A\\Device\\HarddiskVolume[0-9]+\z"), "device-mapping");
            DevicePrefix = device.ToString();
            trace = new Trace("azureauth-confidential-wsl-108-D0-" + nonce, Guid.ParseExact(nonce, "N"));
            trace.Start();
            for (int index = 0; index < 2; index++)
            {
                ObserverProgram.Before(calibrationEnd);
                bool gated = index == 0;
                string[] args = [gated ? "--calibration-gated" : "--calibration-fast", nonce];
                var input = new InputPipe(gated); inputs.Add(input);
                var output = new MemoryPipe(0); outputs.Add(output);
                var error = new MemoryPipe(0); errors.Add(error);
                var target = new Target(plan.ProductImage, Native.CommandLine(plan.ProductImage, args).ToString(), 0, 5, false);
                target.ReadyQpc = ObserverProgram.Now;
                target.LaunchEnd = ObserverProgram.Add(target.ReadyQpc, 2000);
                lock (TargetLock) { Targets.Add(target); targets.Add(target); }
                // job=null uses the contained worker's ordinary inheritance. No worker
                // Job handle exists; the supervisor retains the sole Job handle.
                Child child = Native.StartSuspended(plan.ProductImage, args, plan.WorkingDirectory, input, output, error, null);
                children.Add(child);
                lock (TargetLock)
                {
                    uint pid = TraceNative.GetProcessId(child.Process.DangerousGetHandle());
                    Require(pid != 0 && (target.Pid == 0 || target.Pid == pid), "calibration-creation-pid");
                    target.Pid = pid; target.CreationFileTime = child.CreatedFileTime;
                    target.Handle = child.Process.DangerousGetHandle(); target.BorrowedHandle = true;
                    target.HadHandle = true; target.OpenAttempted = true;
                }
                child.ResumeOnce();
                long childEnd = Math.Min(calibrationEnd, ObserverProgram.Add(target.ReadyQpc, 5000));
                bool closed = false, complete = false; long closeBegan = 0;
                for (int polls = 0; polls < 500 && ObserverProgram.Now < childEnd; polls++)
                {
                    Require(Failure == null && !output.Failed && !error.Failed, "calibration-capture");
                    lock (TargetLock)
                    {
                        if (gated && !closed && target.Starts == 1)
                        {
                            Require(target.Ends == 0 && !child.Exited(), "calibration-gated-live");
                            closeBegan = ObserverProgram.Now;
                            closed = true; // No second close attempt.
                            input.CloseWriter();
                            childEnd = Math.Min(childEnd, ObserverProgram.Add(closeBegan, 1000));
                        }
                        if (target.Ends == 1 && target.ObserveHandle() &&
                            output.Done && output.Eof && error.Done && error.Eof)
                        { complete = true; break; }
                    }
                    Thread.Sleep(10);
                }
                Require(complete && ObserverProgram.Now < childEnd && child.ExitCode() == 0 &&
                    output.Bytes.Length == 0 && error.Bytes.Length == 0, "calibration-complete");
                lock (TargetLock)
                {
                    Require(target.CompleteIdentity && target.HadHandle && target.HandleSignaled &&
                        target.CreationFileTime == child.CreatedFileTime && target.StartQpc >= target.ReadyQpc &&
                        target.StartQpc <= target.LaunchEnd && target.EndQpc <= childEnd, "calibration-original-join");
                    if (gated)
                    {
                        Require(closed, "calibration-close-missing");
                        int closeUpper = AnchorHandshake.ConservativeUpperMilliseconds(closeBegan, target.EndQpc);
                        Require(closeUpper is >= 1 and <= 1000, "calibration-close-bound");
                        gatedWitness = true;
                    }
                    else fastWitness = true;
                }
            }
        }
        catch (Exception caught)
        {
            first = caught is SafeFailure safe ? safe.Fault : Fault.Trace;
            TerminalEnd = Math.Min(TerminalEnd, ObserverProgram.Add(ObserverProgram.Now, 10000));
        }
        finally
        {
            // Close any still-held synthetic writer once. Never infer exit from close.
            foreach (InputPipe input in inputs) { try { input.CloseWriter(); } catch { ResourceUncertain = true; } }
            try { if (trace != null) trace.StopAndDrain(Math.Min(first == Fault.None ? WorkEnd : TerminalEnd,
                ObserverProgram.Add(ObserverProgram.Now, 9000))); }
            catch { if (first == Fault.None) first = Fault.Trace; ResourceUncertain = true; }
            lock (TargetLock)
            {
                result.TraceStopped = trace != null && trace.Stopped;
                result.TraceDrained = trace != null && trace.Drained;
                result.EventsLost = trace?.EventsLost ?? -1; result.LogLost = trace?.LogBuffersLost ?? -1;
                result.RealTimeLost = trace?.RealTimeBuffersLost ?? -1; result.Callbacks = trace?.Callbacks ?? 0;
                result.ZeroLoss = result.EventsLost == 0 && result.LogLost == 0 && result.RealTimeLost == 0;
                result.StartMatched = targets.Count == 2 && targets.TrueForAll(t => t.Starts == 1);
                result.EndMatched = targets.Count == 2 && targets.TrueForAll(t => t.Ends == 1);
                result.HandleRetained = targets.Count == 2 && targets.TrueForAll(t => t.HadHandle);
                result.HandleExited = result.HandleRetained && targets.TrueForAll(t => t.HandleSignaled);
                result.NativeComplete = gatedWitness && fastWitness && result.StartMatched && result.EndMatched &&
                    result.HandleRetained && result.HandleExited && result.TraceStopped && result.TraceDrained &&
                    result.ZeroLoss && Failure == null && !ResourceUncertain;
                result.TimingValid = gatedWitness && fastWitness;
                result.ExpectedExit = targets.Count == 2 && targets.TrueForAll(t => t.Ends == 1 && t.Exit == 0);
                if (result.NativeComplete)
                {
                    result.Exit = 0; result.DurationMs = 0;
                    foreach (Target target in targets) result.DurationMs = Math.Max(result.DurationMs,
                        ObserverProgram.Milliseconds(target.StartQpc, target.EndQpc));
                }
                foreach (Target target in targets) target.Close();
            }
            foreach (Child child in children) child.Dispose();
            foreach (InputPipe input in inputs) input.Dispose();
            foreach (MemoryPipe output in outputs) output.Dispose();
            foreach (MemoryPipe error in errors) error.Dispose();
        }
        result.FailureKind = first != Fault.None ? first :
            result.NativeComplete && result.TimingValid && result.ExpectedExit ? Fault.None : Fault.Lifetime;
        return result;
    }

    private sealed class Target
    {
        internal readonly string Image, Command;
        internal readonly int ExpectedExit, TimeoutSeconds;
        internal readonly bool StopPremiseAccepted;
        internal int Starts, Ends, Exit, Version, PointerBytes;
        internal uint Pid; internal ulong Key;
        internal long StartQpc, EndQpc, CreationFileTime, ReadyQpc, LaunchEnd;
        internal IntPtr Handle;
        internal bool HadHandle, HandleSignaled, Forced, OpenAttempted, BorrowedHandle;
        internal bool AnchorSampled, AnchorAckPublished;
        internal long AnchorQpc;
        internal Target(string image, string command, int expectedExit, int timeout, bool stopAccepted)
        { Image = image; Command = command; ExpectedExit = expectedExit; TimeoutSeconds = timeout; StopPremiseAccepted = stopAccepted; }
        internal bool CompleteIdentity => Starts == 1 && Ends == 1 && Key != 0 && Pid != 0 &&
            EndQpc >= StartQpc && PointerBytes == 8 && (Version == 3 || Version == 4);
        internal bool ObserveHandle()
        {
            if (Handle == IntPtr.Zero) return !HadHandle;
            uint wait = TraceNative.WaitForSingleObject(Handle, 0);
            Require(wait == 0 || wait == 258, "target-wait");
            if (wait != 0) return false;
            HandleSignaled = true;
            Require(TraceNative.GetExitCodeProcess(Handle, out uint code), "target-exit");
            Require(Ends != 1 || code == unchecked((uint)Exit), "target-exit-disagreement");
            return true;
        }
        internal void TryOpenOriginal()
        {
            uint pid;
            lock (TargetLock)
            {
                if (OpenAttempted || Starts != 1 || Ends == 1) return;
                OpenAttempted = true; pid = Pid;
            }
            // One optional late handle, never called a creation handle. Ownership depends
            // on admitted sole-launch/single-use-image correlation, not PID/image alone.
            IntPtr candidate = TraceNative.OpenProcess(StopPremiseAccepted ? 0x00101001U : 0x00101000U, false, pid);
            if (candidate == IntPtr.Zero) return;
            try
            {
                Require(TraceNative.GetProcessId(candidate) == pid && SameImage(TraceNative.Image(candidate), Image), "late-identity");
                Require(TraceNative.GetProcessTimes(candidate, out long created, out _, out _, out _) && created > 0, "late-created");
                // Outside-Job topology is the admitted direct-launch premise. No Job
                // handle is opened here, and this late handle is not creation evidence.
                lock (TargetLock) { Handle = candidate; HadHandle = true; CreationFileTime = created; candidate = IntPtr.Zero; }
            }
            finally { if (candidate != IntPtr.Zero) TraceNative.CloseHandle(candidate); }
        }
        internal void StopIfNeeded(long originalTerminalEnd)
        {
            if (Handle == IntPtr.Zero) { if (Ends != 1) ResourceUncertain = true; return; }
            if (ObserveHandle()) return;
            if (!StopPremiseAccepted || Forced) { ResourceUncertain = true; return; }
            ObserverProgram.Before(originalTerminalEnd);
            Forced = true;
            Require(TraceNative.TerminateProcess(Handle, 211), "target-stop");
            Require(TraceNative.WaitForSingleObject(Handle, (uint)ObserverProgram.Remaining(originalTerminalEnd, 1000)) == 0, "target-stop-wait");
            HandleSignaled = true;
        }
        internal void Close() { if (BorrowedHandle) Handle = IntPtr.Zero; else TraceNative.Close(ref Handle); }
    }
    private sealed class ProcessEvent
    {
        internal uint Pid;
        internal ulong Key;
        internal int Exit, Version, Width;
        internal long Qpc;
        internal string Image, Command;
    }
    private static readonly List<ProcessEvent> EarlyEnds = new List<ProcessEvent>();
    private static void Associate(ProcessEvent e, int opcode)
    {
        lock (TargetLock)
        {
            if (opcode == 1)
            {
                Target target = null; bool imageMatched = false;
                foreach (Target t in Targets)
                {
                    if (SameImage(e.Image, t.Image))
                    {
                        imageMatched = true;
                        if (e.Command == t.Command) { Require(target == null, "ambiguous-target-command"); target = t; }
                    }
                    else if (string.Equals(e.Image, Path.GetFileName(t.Image), StringComparison.OrdinalIgnoreCase))
                        throw new FailureException("short-target-image");
                }
                Require(!imageMatched || target != null, "target-command");
                if (target == null) return;
                Require(e.Command == target.Command && target.Starts == 0 && e.Key != 0 &&
                    e.Pid != 0 && e.Width == 8 && target.ReadyQpc != 0 &&
                    e.Qpc >= target.ReadyQpc && e.Qpc <= target.LaunchEnd, "target-start-identity");
                if (target.Pid != 0) Require(target.Pid == e.Pid, "creation-event-pid");
                target.Starts = 1; target.Pid = e.Pid; target.Key = e.Key; target.StartQpc = e.Qpc;
                target.Version = e.Version; target.PointerBytes = e.Width;
                for (int i = EarlyEnds.Count - 1; i >= 0; i--)
                    if (EarlyEnds[i].Pid == e.Pid && EarlyEnds[i].Key == e.Key)
                    { ApplyEnd(target, EarlyEnds[i]); EarlyEnds.RemoveAt(i); }
            }
            else
            {
                foreach (Target t in Targets)
                    if (t.Starts == 1 && t.Pid == e.Pid && t.Key == e.Key) { ApplyEnd(t, e); return; }
                Require(EarlyEnds.Count < 256, "early-end-cap");
                // No unrelated image, command, SID or parent data is retained in this bounded join queue.
                e.Image = null; e.Command = null; EarlyEnds.Add(e);
            }
        }
    }
    private static void ApplyEnd(Target target, ProcessEvent e)
    {
        Require(target.Ends == 0 && e.Width == target.PointerBytes && e.Version == target.Version &&
            e.Qpc >= target.StartQpc, "target-end-identity");
        target.Ends = 1; target.EndQpc = e.Qpc; target.Exit = e.Exit;
    }
    private static bool SameImage(string actual, string expected)
    {
        if (actual.StartsWith(DevicePrefix + "\\", StringComparison.OrdinalIgnoreCase))
            actual = "C:" + actual.Substring(DevicePrefix.Length);
        if (actual.StartsWith(@"\\?\C:\", StringComparison.OrdinalIgnoreCase)) actual = actual.Substring(4);
        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }
    private sealed class Trace
    {
        private readonly string name;
        private readonly Guid guid;
        private IntPtr properties, logfile, namePointer;
        private ulong session, consumer = ulong.MaxValue;
        private Thread worker;
        private TraceNative.RecordCallback callback;
        private TraceNative.BufferCallback bufferCallback;
        private bool owned, stopAttempted, consumerCloseAttempted, finalized;
        private uint processResult = uint.MaxValue;
        private long copiedBytes;
        internal bool Stopped, Drained;
        internal int Callbacks, EventsLost = -1, LogBuffersLost = -1, RealTimeBuffersLost = -1;
        internal Trace(string name, Guid guid) { this.name = name; this.guid = guid; }
        internal void Start()
        {
            byte[] nameBytes = Utf16.GetBytes(name + "\0");
            Require(nameBytes.Length <= 1024, "trace-name");
            properties = TraceNative.Allocate(120 + nameBytes.Length);
            Marshal.WriteInt32(properties, 0, 120 + nameBytes.Length);
            Marshal.Copy(guid.ToByteArray(), 0, IntPtr.Add(properties, 24), 16);
            Marshal.WriteInt32(properties, 40, 1); Marshal.WriteInt32(properties, 44, 0x00020000);
            Marshal.WriteInt32(properties, 48, 64); Marshal.WriteInt32(properties, 52, 4);
            Marshal.WriteInt32(properties, 56, 8); Marshal.WriteInt32(properties, 64, 0x12000100);
            Marshal.WriteInt32(properties, 68, 1); Marshal.WriteInt32(properties, 72, 0x10000001);
            Marshal.WriteInt32(properties, 116, 120);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(properties, 120), nameBytes.Length);
            Require(TraceNative.StartTrace(out session, name, properties) == 0, "trace-start"); owned = true;
            Require(TraceNative.ControlTrace(session, name, properties, 0) == 0, "trace-query");
            int minimum = Marshal.ReadInt32(properties, 52), maximum = Marshal.ReadInt32(properties, 56);
            int allocated = Marshal.ReadInt32(properties, 80);
            Require(Marshal.ReadInt32(properties, 48) == 64 && minimum >= 2 && minimum <= 8 &&
                maximum >= minimum && maximum <= 8 && allocated >= 2 && allocated <= 8 &&
                Marshal.ReadInt32(properties, 64) == 0x12000100 && Marshal.ReadInt32(properties, 72) == 0x10000001,
                "trace-buffer-shape");
            logfile = TraceNative.Allocate(448); namePointer = Marshal.StringToHGlobalUni(name);
            Marshal.WriteIntPtr(logfile, 8, namePointer); Marshal.WriteInt32(logfile, 28, 0x10001100);
            callback = OnRecord; bufferCallback = OnBuffer;
            Marshal.WriteIntPtr(logfile, 400, Marshal.GetFunctionPointerForDelegate(bufferCallback));
            Marshal.WriteIntPtr(logfile, 424, Marshal.GetFunctionPointerForDelegate(callback));
            consumer = TraceNative.OpenTrace(logfile);
            Require(consumer != ulong.MaxValue, "trace-open");
            ManualResetEvent entered = new ManualResetEvent(false);
            worker = new Thread(delegate()
            {
                entered.Set(); ulong handle = consumer;
                try { processResult = TraceNative.ProcessTrace(ref handle, 1, IntPtr.Zero, IntPtr.Zero); }
                catch { processResult = uint.MaxValue; Fail("consumer-worker"); }
            }); worker.IsBackground = true; worker.Start();
            Require(entered.WaitOne((int)Remaining(1000)), "consumer-ready");
            entered.Close();
        }
        private uint OnBuffer(IntPtr data)
        {
            try
            {
                if (Marshal.ReadInt32(data, 416) != 0) Fail("consumer-buffer-loss");
                return Failure == null ? 1U : 0U;
            }
            catch { Fail("buffer-callback"); return 0; }
        }
        private void OnRecord(IntPtr record)
        {
            try
            {
                if (Failure != null) return;
                Require(Interlocked.Increment(ref Callbacks) <= 65536, "callback-limit");
                byte[] provider = new byte[16]; Marshal.Copy(IntPtr.Add(record, 24), provider, 0, 16);
                if (new Guid(provider) != new Guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c")) return;
                int opcode = Marshal.ReadByte(record, 45); if (opcode != 1 && opcode != 2) return;
                int version = Marshal.ReadByte(record, 42);
                Require(version == 3 || version == 4, "event-version");
                int flags = (ushort)Marshal.ReadInt16(record, 4);
                Require((flags & 0x60) == 0x20 || (flags & 0x60) == 0x40, "event-width");
                int width = (flags & 0x40) != 0 ? 8 : 4;
                int length = (ushort)Marshal.ReadInt16(record, 86);
                Require(length > 0 && Interlocked.Add(ref copiedBytes, length) <= 16777216, "event-byte-cap");
                byte[] raw = new byte[length]; Marshal.Copy(Marshal.ReadIntPtr(record, 96), raw, 0, length);
                ProcessEvent e = Decode(raw, version, width); e.Qpc = Marshal.ReadInt64(record, 16);
                Associate(e, opcode); Array.Clear(raw, 0, raw.Length);
            }
            catch (FailureException ex) { Fail(ex.Code); }
            catch { Fail("event-decode"); }
        }
        internal void StopAndDrain(long deadline)
        {
            if (finalized) return;
            if (!owned) { FreeIfFinished(); return; }
            if (!stopAttempted)
            {
                stopAttempted = true;
                uint result = TraceNative.ControlTrace(session, name, properties, 1);
                if (result == 0)
                {
                    Stopped = true;
                    EventsLost = Marshal.ReadInt32(properties, 88);
                    LogBuffersLost = Marshal.ReadInt32(properties, 96);
                    RealTimeBuffersLost = Marshal.ReadInt32(properties, 100);
                }
                else Fail("trace-stop");
            }
            if (worker != null)
            {
                int remaining = ObserverProgram.Remaining(deadline, 9000);
                if (!worker.Join(remaining))
                {
                    Fail("consumer-drain"); CloseConsumer();
                    Require(worker.Join(ObserverProgram.Remaining(deadline, 100)), "consumer-live");
                }
                Drained = Stopped && processResult == 0 && !consumerCloseAttempted;
            }
            CloseConsumer();
            FreeIfFinished();
            Require(Stopped && Drained && EventsLost == 0 && LogBuffersLost == 0 && RealTimeBuffersLost == 0,
                "trace-finalization");
            finalized = true;
        }
        private void CloseConsumer()
        {
            if (consumer == ulong.MaxValue || consumerCloseAttempted) return;
            consumerCloseAttempted = true;
            uint result = TraceNative.CloseTrace(consumer);
            Require(result == 0 || result == 7007, "consumer-close");
        }
        private void FreeIfFinished()
        {
            if (worker != null && worker.IsAlive) return; // Retain callbacks/buffers until process teardown.
            TraceNative.Free(ref logfile); TraceNative.Free(ref namePointer);
            if (!owned || Stopped) TraceNative.Free(ref properties);
        }
    }

    private static ProcessEvent Decode(byte[] raw, int version, int width)
    {
        ProcessEvent e = new ProcessEvent(); e.Version = version; e.Width = width;
        e.Key = ReadUnsigned(raw, 0, width); e.Pid = (uint)ReadUnsigned(raw, width, 4);
        e.Exit = unchecked((int)ReadUnsigned(raw, 16 + width - 4, 4));
        int sid = (version == 4 ? 28 : 24) + 2 * (width - 4);
        int image;
        if (ReadUnsigned(raw, sid, 4) == 0) image = sid + 4;
        else
        {
            int token = 2 * width;
            Require(ReadUnsigned(raw, sid + token, 1) == 1, "sid-revision");
            int authorities = (int)ReadUnsigned(raw, sid + token + 1, 1);
            Require(authorities <= 15, "sid-count"); image = sid + token + 8 + 4 * authorities;
        }
        int next = image; e.Image = ReadString(raw, ref next, false);
        e.Command = ReadString(raw, ref next, true);
        if (version == 4) { ReadString(raw, ref next, true); ReadString(raw, ref next, true); }
        Require(next == raw.Length, "event-tail"); return e;
    }
    private static ulong ReadUnsigned(byte[] raw, int at, int size)
    {
        Require(at >= 0 && size > 0 && at <= raw.Length - size, "event-range");
        ulong value = 0; for (int i = 0; i < size; i++) value |= ((ulong)raw[at + i]) << (8 * i);
        return value;
    }
    private static string ReadString(byte[] raw, ref int at, bool unicode)
    {
        int start = at, step = unicode ? 2 : 1;
        for (int count = 0; count <= 32768; count++, at += step)
        {
            Require(at >= 0 && at <= raw.Length - step, "event-string-range");
            if (raw[at] == 0 && (!unicode || raw[at + 1] == 0))
            {
                string result = unicode ? Utf16.GetString(raw, start, at - start) : Utf8.GetString(raw, start, at - start);
                at += step; return result;
            }
        }
        throw new FailureException("event-string-cap");
    }

    private static class TraceNative
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void RecordCallback(IntPtr record);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate uint BufferCallback(IntPtr logfile);
        internal static IntPtr Allocate(int size)
        {
            Require(size > 0 && size <= 65536, "native-allocation-cap");
            IntPtr value = Marshal.AllocHGlobal(size);
            for (int i = 0; i < size; i++) Marshal.WriteByte(value, i, 0); return value;
        }
        internal static void Free(ref IntPtr value)
        { if (value != IntPtr.Zero) { Marshal.FreeHGlobal(value); value = IntPtr.Zero; } }
        internal static void Close(ref IntPtr value)
        {
            if (value == IntPtr.Zero) return;
            if (!CloseHandle(value)) { ResourceUncertain = true; Fail("handle-close"); return; }
            value = IntPtr.Zero;
        }
        internal static string Image(IntPtr process)
        {
            StringBuilder value = new StringBuilder(32768); int length = value.Capacity;
            Require(QueryFullProcessImageName(process, 0, value, ref length) && length > 0 && length < value.Capacity,
                "process-image"); return value.ToString();
        }
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryDosDeviceW", SetLastError = true)]
        internal static extern uint QueryDosDevice(string name, StringBuilder target, int length);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint GetProcessId(IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(IntPtr process, out uint exit);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(IntPtr process, uint exit);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder image, ref int length);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "StartTraceW")]
        internal static extern uint StartTrace(out ulong session, string name, IntPtr properties);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "ControlTraceW")]
        internal static extern uint ControlTrace(ulong session, string name, IntPtr properties, uint control);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "OpenTraceW", SetLastError = true)]
        internal static extern ulong OpenTrace(IntPtr logfile);
        [DllImport("advapi32.dll")] internal static extern uint ProcessTrace(ref ulong handles, uint count, IntPtr start, IntPtr end);
        [DllImport("advapi32.dll")] internal static extern uint CloseTrace(ulong consumer);
    }
}
