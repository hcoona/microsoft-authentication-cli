#nullable enable
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
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
    internal static void Need(bool value,[CallerLineNumber] int line=0)
    { if(!value){DirectFailure.Remember(3,line);throw new SafeFailure(Fault.Admission);} }
    internal static int Milliseconds(long start, long end) => checked((int)
        (((end - start) * 1000 + Stopwatch.Frequency - 1) / Stopwatch.Frequency));

    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted) return 125;
        long entry = Now; bool worker = args.Length > 0 && args[0] == "--worker";
        DirectFailure.Origin=worker?1:2; DirectFailure.Stage=1;
        try
        {
            ObserverProgram.Need(OperatingSystem.IsWindows() && IntPtr.Size == 8 && Stopwatch.IsHighResolution &&
                args.Length is 5 or 6 or 7 && Enum.TryParse(args[1], false, out Slot slot) && slot.ToString() == args[1] &&
                Regex.IsMatch(args[2], "\\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\\z"));
            slot = Enum.Parse<Slot>(args[1], false);
            bool fixture=slot==Slot.D0 || DirectRoles.Fixture(slot);
            DirectFailure.Enabled=fixture;
            if(slot==Slot.D0 && worker)FailureDetail.CheckCodec();
            ObserverProgram.Need(worker ? args.Length == (fixture?7:6) : args.Length == 5 && args[0] == "--supervisor");
            long workEnd=Add(entry,145000);
            if(worker)ObserverProgram.Need(long.TryParse(args[5],NumberStyles.None,CultureInfo.InvariantCulture,out workEnd) &&
                workEnd>Now && workEnd<=Add(entry,145000));
            if(slot==Slot.D0 && worker)AcceptedDirectInputs.CheckBaselineParts(workEnd);
            DirectFailure.Stage=2;
            AdmissionCatalog.Configure(args[3],args[4],slot,args[2],worker,workEnd,worker && fixture?args[6]:null);
            PublicPlan plan = AdmissionCatalog.LoadPublicPlan(slot, args[2]); AdmissionCatalog.Validate(plan);
            DirectFailure.Stage=3;
            using IDisposable lease = AdmissionCatalog.HoldAcceptedInputs(plan, slot, args[2], worker);
            if (!worker) return Supervise(plan, slot, args[2], entry);
            DirectFailure.Stage=4;
            Observation result = slot == Slot.D0 ? EtwObserver.RunCalibration(plan, args[2], workEnd) :
                EtwObserver.Run(plan, slot, args[2], workEnd);
            WriteFrame(fixture && !result.Passed ?
                DirectFailure.Capture(result.FailureKind == Fault.None ? Fault.Lifetime : result.FailureKind).Encode() :
                result.Encode(slot)); return result.Passed ? 0 : 1;
        }
        catch (Exception caught)
        {
            FailureDetail detail=DirectFailure.Capture(caught is SafeFailure safe ? safe.Fault : Fault.Native);
            if (worker && !frameAttempted)
                try { WriteFrame(DirectFailure.Enabled?detail.Encode():[79, 87, 70, 49, (byte)detail.Fault]); } catch { }
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
        FailureDetail? failure=null;
        uint expectedTotal = slot == Slot.D0 ? 3u : 1u;
        try
        {
            try
            {
                DirectFailure.Stage=5;
                Before(workEnd);
                // Real product remains outside this Job. D0 alone admits two synthetic children.
                job = Native.NewJob(JobName(slot, nonce), slot == Slot.D0 ? 2 : 0);
                output = new MemoryPipe(40); error = new MemoryPipe(1); input = new InputPipe(false);
                worker = Native.StartSuspended(plan.ObserverImage,
                    AdmissionCatalog.WorkerArguments(slot,nonce,workEnd),
                    plan.WorkingDirectory, input, output, error, job);
                Before(workEnd); worker.ResumeOnce();
                DirectFailure.Stage=6;
                for (int polls = 0; polls < 15500; polls++)
                {
                    Before(workEnd);
                    if (output.Failed || error.Failed) throw new SafeFailure(Fault.Capture);
                    Native.Accounting count = Native.Query(job); jobZero = count.ActiveProcesses == 0; total = count.TotalProcesses;
                    ObserverProgram.Need(total <= expectedTotal);
                    if (worker.Exited() && jobZero && output.Done && output.Eof && error.Done && error.Eof)
                    { complete = true; exit = worker.ExitCode(); break; }
                    Thread.Sleep(10);
                }
                Before(workEnd); ObserverProgram.Need(complete && total >= 1 && total <= expectedTotal && error.Bytes.Length == 0);
                ReadOnlySpan<byte> frame = output.Bytes.Span;
                DirectFailure.Stage=7;
                if (frame.Length == 5 && frame[..4].SequenceEqual("OWF1"u8))
                {
                    Need(frame[4] > 0 && frame[4] <= (byte)Fault.Lifetime); fault = (Fault)frame[4];
                    failure=new((int)fault,1,0,0,0,0,-1);
                }
                else if(DirectFailure.Enabled && frame.Length>=4 &&
                    (frame[..4].SequenceEqual("OWF2"u8) || frame[..4].SequenceEqual("OWF3"u8) ||
                     frame[..4].SequenceEqual("OWF4"u8)))
                { Need(FailureDetail.TryDecode(frame,out FailureDetail detail));failure=detail;fault=(Fault)detail.Fault; }
                else
                {
                    result = Observation.Decode(frame, slot); fault = result.FailureKind;
                    if(fault!=Fault.None)failure=new((int)fault,1,4,0,0,0,-1);
                }
                terminalEnd = Math.Min(terminalEnd, Add(Now, 10000));
            }
            catch (Exception caught)
            {
                failure = DirectFailure.Capture(caught is SafeFailure safe ? safe.Fault : Fault.Native);
                fault = (Fault)failure.Value.Fault;
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
            DirectFailure.Stage=8;
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
            if(DirectFailure.Enabled)record["failure"]=passed?null!:
                (failure??new FailureDetail((int)fault,2,8,0,0,0,-1)).Record();
            // D0 aggregates both original creation-handle/START/END/EOF joins. It
            // supplies calibration evidence only, never real-product acceptance.
            PublicRecords.Publish(plan, "observer-final.json", record);
            Before(terminalEnd); return passed ? 0 : 1;
        }
        finally { worker?.Dispose(); job?.Dispose(); input?.Dispose(); output?.Dispose(); error?.Dispose(); }
    }
    internal static string JobName(Slot slot, string nonce) => "Local\\azureauth-confidential-wsl-108-" + slot + "-" + nonce;
}

// Fixed numeric diagnostics for synthetic roles only. No message, path or input value
// enters this channel. The admitted source and ordinal catalog identify each location.
internal readonly record struct TraceQuery(uint BufferSize,uint MinimumBuffers,uint MaximumBuffers,
    uint NumberOfBuffers,uint LogFileMode,uint EnableFlags)
{
    internal bool MatchesExpected => BufferSize==64 && MinimumBuffers is >=2 and <=8 &&
        MaximumBuffers>=MinimumBuffers && MaximumBuffers<=8 && NumberOfBuffers is >=2 and <=8 &&
        LogFileMode==0x12000100 && EnableFlags==0x10000001;
    internal object Record()=>new {available=1,bufferSize=BufferSize,minimumBuffers=MinimumBuffers,
        maximumBuffers=MaximumBuffers,numberOfBuffers=NumberOfBuffers,logFileMode=LogFileMode,enableFlags=EnableFlags};
}

internal readonly record struct FailureDetail(int Fault,int Origin,int Stage,int Source,int Line,int InputOrdinal,int OpenError,
    uint NativeStatus=uint.MaxValue,int TraceState=-1,TraceQuery? Query=null)
{
    private bool Extended => Source==4 || NativeStatus!=uint.MaxValue || TraceState!=-1;
    private bool QueryContext => Fault==8 && Origin==1 && Stage==4 && Source==4 &&
        Line is >=1 and <=100000 && InputOrdinal==0 && OpenError==-1 && NativeStatus==uint.MaxValue;
    internal object Record()=>Query is TraceQuery query ?
        new {fault=Fault,origin=Origin,stage=Stage,source=Source,line=Line,inputOrdinal=InputOrdinal,
            openError=OpenError,nativeStatus=NativeStatus,traceState=TraceState,traceQuery=query.Record()} : Extended ?
        new {fault=Fault,origin=Origin,stage=Stage,source=Source,line=Line,inputOrdinal=InputOrdinal,
            openError=OpenError,nativeStatus=NativeStatus,traceState=TraceState} :
        new {fault=Fault,origin=Origin,stage=Stage,source=Source,line=Line,inputOrdinal=InputOrdinal,openError=OpenError};
    internal byte[] Encode()
    {
        if(Query is TraceQuery query)
        {
            if(!QueryContext || TraceState<0 || !ValidTraceState(TraceState) || (TraceState&3)!=3 || query.MatchesExpected)
                throw new SafeFailure(ConfidentialWsl.Fault.Protocol);
            // OWF4 implies the fixed trace-shape failure context; the channel stays 40 bytes.
            byte[] queried=new byte[40];"OWF4"u8.CopyTo(queried);
            BinaryPrimitives.WriteInt32LittleEndian(queried.AsSpan(4),Line);
            BinaryPrimitives.WriteInt32LittleEndian(queried.AsSpan(8),TraceState);
            BinaryPrimitives.WriteInt32LittleEndian(queried.AsSpan(12),1);
            uint[] queryValues=[query.BufferSize,query.MinimumBuffers,query.MaximumBuffers,
                query.NumberOfBuffers,query.LogFileMode,query.EnableFlags];
            for(int i=0;i<queryValues.Length;i++)BinaryPrimitives.WriteUInt32LittleEndian(queried.AsSpan(16+4*i),queryValues[i]);
            return queried;
        }
        byte[] frame=new byte[Extended?40:32];
        if(Extended)"OWF3"u8.CopyTo(frame);else "OWF2"u8.CopyTo(frame);
        int[] values=[Fault,Origin,Stage,Source,Line,InputOrdinal,OpenError];
        for(int i=0;i<values.Length;i++)BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(4+4*i),values[i]);
        if(Extended)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(32),NativeStatus);
            BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(36),TraceState);
        }
        return frame;
    }
    internal static bool ValidTraceState(int state) => state==-1 ||
        (state is >=0 and <=31 && ((state&2)==0 || (state&1)!=0) &&
        ((state&4)==0 || (state&2)!=0) && ((state&8)==0 || (state&4)!=0) &&
        ((state&16)==0 || (state&8)!=0));
    internal static bool TryDecode(ReadOnlySpan<byte> frame,out FailureDetail result)
    {
        result=default;
        if(frame.Length==40 && frame[..4].SequenceEqual("OWF4"u8))
        {
            int line=BinaryPrimitives.ReadInt32LittleEndian(frame[4..]);
            int state=BinaryPrimitives.ReadInt32LittleEndian(frame[8..]);
            if(line is <1 or >100000 || state<0 || !ValidTraceState(state) || (state&3)!=3 ||
                BinaryPrimitives.ReadInt32LittleEndian(frame[12..])!=1)return false;
            var query=new TraceQuery(BinaryPrimitives.ReadUInt32LittleEndian(frame[16..]),
                BinaryPrimitives.ReadUInt32LittleEndian(frame[20..]),BinaryPrimitives.ReadUInt32LittleEndian(frame[24..]),
                BinaryPrimitives.ReadUInt32LittleEndian(frame[28..]),BinaryPrimitives.ReadUInt32LittleEndian(frame[32..]),
                BinaryPrimitives.ReadUInt32LittleEndian(frame[36..]));
            if(query.MatchesExpected)return false;
            result=new FailureDetail(8,1,4,4,line,0,-1,uint.MaxValue,state,query);return true;
        }
        bool extended=frame.Length==40 && frame[..4].SequenceEqual("OWF3"u8);
        if(!extended && (frame.Length!=32 || !frame[..4].SequenceEqual("OWF2"u8)))return false;
        int[] values=new int[7];
        for(int i=0;i<values.Length;i++)values[i]=BinaryPrimitives.ReadInt32LittleEndian(frame[(4+4*i)..]);
        var value=new FailureDetail(values[0],values[1],values[2],values[3],values[4],values[5],values[6],
            extended?BinaryPrimitives.ReadUInt32LittleEndian(frame[32..]):uint.MaxValue,
            extended?BinaryPrimitives.ReadInt32LittleEndian(frame[36..]):-1);
        if(value.Fault is <1 or >10 || value.Origin!=1 || value.Stage is <1 or >4 ||
            value.Source<0 || value.Source>(extended?4:3) || (value.Source==0?value.Line!=0:value.Line is <1 or >100000) ||
            value.InputOrdinal is <0 or >200 || value.OpenError< -1)return false;
        if(extended && (value.Stage!=4 || !value.Extended || !ValidTraceState(value.TraceState) ||
            (value.Source!=4 && value.NativeStatus!=uint.MaxValue)))return false;
        result=value;return true;
    }
    internal static void CheckCodec()
    {
        // Pure codec checks in the existing D0 worker; no I/O or process creation.
        static void Check(bool value){if(!value)throw new SafeFailure(ConfidentialWsl.Fault.Expectation);}
        var known=new FailureDetail(2,1,2,1,88,200,5);
        byte[] frame=known.Encode();Check(TryDecode(frame,out FailureDetail decoded) && decoded==known);
        var unknown=new FailureDetail(3,1,4,0,0,0,-1);
        Check(TryDecode(unknown.Encode(),out decoded) && decoded==unknown);
        Check(!TryDecode(frame.AsSpan(0,31),out _));Check(!TryDecode(new byte[33],out _));
        byte[] bad=(byte[])frame.Clone();bad[0]=0;Check(!TryDecode(bad,out _));
        int[] invalid=[0,2,5,4,0,201,-2];
        for(int i=0;i<invalid.Length;i++)
        {
            bad=(byte[])frame.Clone();BinaryPrimitives.WriteInt32LittleEndian(bad.AsSpan(4+4*i),invalid[i]);
            Check(!TryDecode(bad,out _));
        }
        Check(!TryDecode((known with {Source=0}).Encode(),out _));
        var trace=new FailureDetail(8,1,4,4,437,0,-1,5,1);
        byte[] traceFrame=trace.Encode();Check(traceFrame.Length==40);
        Check(TryDecode(traceFrame,out decoded) && decoded==trace);
        Check(TryDecode((trace with {NativeStatus=uint.MaxValue,TraceState=31}).Encode(),out _));
        Check(TryDecode((unknown with {TraceState=0}).Encode(),out _));
        Check(!TryDecode(traceFrame.AsSpan(0,39),out _));Check(!TryDecode(new byte[41],out _));
        Check(!TryDecode((trace with {Stage=3}).Encode(),out _));
        Check(!TryDecode((trace with {Source=3}).Encode(),out _));
        foreach(int state in new[]{-2,2,4,8,16,32})
            Check(!TryDecode((trace with {TraceState=state}).Encode(),out _));
        foreach(int state in new[]{-1,0,1,3,7,15,31})
            Check(TryDecode((trace with {TraceState=state}).Encode(),out _));
        var shape=new TraceQuery(64,4,8,4,0x12000100,0x10000001);
        Check(shape.MatchesExpected);
        foreach(var query in new[]{shape with {BufferSize=uint.MaxValue},shape with {MinimumBuffers=1},
            shape with {MaximumBuffers=3},shape with {NumberOfBuffers=9},
            shape with {LogFileMode=0},shape with {EnableFlags=0}})
        {
            var detail=new FailureDetail(8,1,4,4,467,0,-1,uint.MaxValue,15,query);
            byte[] queried=detail.Encode();Check(queried.Length==40);
            Check(TryDecode(queried,out decoded) && decoded==detail);
            Check(!TryDecode(queried.AsSpan(0,39),out _));
            foreach(int availability in new[]{-1,0,2})
            {
                bad=(byte[])queried.Clone();BinaryPrimitives.WriteInt32LittleEndian(bad.AsSpan(12),availability);
                Check(!TryDecode(bad,out _));
            }
            foreach(int state in new[]{-1,0,1,2,4,8,16,32})
            {
                bad=(byte[])queried.Clone();BinaryPrimitives.WriteInt32LittleEndian(bad.AsSpan(8),state);
                Check(!TryDecode(bad,out _));
            }
        }
        var absent=unknown with {TraceState=15};
        Check(TryDecode(absent.Encode(),out decoded) && decoded.Query is null);
        byte[] successful=new FailureDetail(8,1,4,4,467,0,-1,uint.MaxValue,15,
            shape with {BufferSize=0}).Encode();
        BinaryPrimitives.WriteUInt32LittleEndian(successful.AsSpan(16),64);
        Check(!TryDecode(successful,out _));
        byte[] malformed=new FailureDetail(8,1,4,4,467,0,-1,uint.MaxValue,15,
            shape with {BufferSize=0}).Encode();
        BinaryPrimitives.WriteInt32LittleEndian(malformed.AsSpan(4),0);
        Check(!TryDecode(malformed,out _));Check(!TryDecode(new byte[41],out _));
    }
}
internal static class DirectFailure
{
    internal static bool Enabled;
    internal static int Origin,Stage,InputOrdinal;
    private static readonly object Sync=new();
    private static FailureDetail? first;
    private static int traceState=-1;
    internal static void Remember(int source,int line)
    { if(Enabled)lock(Sync)first??=new FailureDetail((int)Fault.Admission,Origin,Stage,source,line,InputOrdinal,-1); }
    internal static void RememberTrace(int line,uint status)
    { if(Enabled)lock(Sync)first??=new FailureDetail((int)Fault.Trace,Origin,Stage,4,line,InputOrdinal,-1,status); }
    internal static void RememberTraceQuery(int line,TraceQuery query)
    { if(Enabled)lock(Sync)first??=new FailureDetail((int)Fault.Trace,Origin,Stage,4,line,InputOrdinal,-1,
        uint.MaxValue,-1,query); }
    internal static void RememberTraceStatus(uint status,[CallerLineNumber] int line=0) => RememberTrace(line,status);
    internal static void SetTraceState(int state)
    { if(Enabled)lock(Sync)traceState=state; }
    internal static FailureDetail Capture(Fault fault)
    {
        lock(Sync)
        {
            if(first is not FailureDetail)
            {
                bool native=ConfidentialNativeCaller.FixtureNativePins.FailedCheckSource==
                    ConfidentialNativeCaller.FixtureCheckSource.NativePins;
                var captured=new FailureDetail((int)fault,Origin,Stage,native?2:0,
                    native?ConfidentialNativeCaller.FixtureNativePins.FailedCheckLine:0,InputOrdinal,
                    ConfidentialNativeCaller.FixtureNativePins.OpenError??-1);
                if(!Enabled)return captured;
                first=captured;
            }
            FailureDetail result=first.Value;
            return result.Origin==1 && result.Stage==4 ? result with {TraceState=traceState} : result;
        }
    }
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
        ObserverProgram.Need(frame.Length == 40 && (slot == Slot.D0 ?
            frame[..4].SequenceEqual("OWK1"u8) : frame[..4].SequenceEqual("OWS2"u8)));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(frame[4..]);
        ObserverProgram.Need((flags & ~8191u) == 0);
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
        ObserverProgram.Need(result.Callbacks is >= 0 and <= 65537 && result.EventsLost >= -1 && result.LogLost >= -1 &&
            result.RealTimeLost >= -1 && result.DurationMs is >= -1 and <= 155000 && Enum.IsDefined(result.FailureKind));
        ObserverProgram.Need(!result.ZeroLoss || result.EventsLost == 0 && result.LogLost == 0 && result.RealTimeLost == 0);
        ObserverProgram.Need(!result.NativeComplete || result.StartMatched && result.EndMatched && result.TraceStopped &&
            result.TraceDrained && result.ZeroLoss && (!result.HandleRetained || result.HandleExited));
        ObserverProgram.Need(!result.HandleExited || result.HandleRetained);
        ObserverProgram.Need(!result.TraceDrained || result.TraceStopped);
        ObserverProgram.Need(!result.ExpectedExit || result.Exit is 0 or 1);
        ObserverProgram.Need(!result.EndByAnchorDeadline || result.AnchorAckPublished &&
            result.NativeComplete && result.TimingValid && result.ExpectedExit && !result.TargetStop &&
            result.FailureKind == Fault.None && result.AnchorUpperMs is >= 1 and <= 1000);
        ObserverProgram.Need(result.EndByAnchorDeadline || result.AnchorUpperMs == -1);
        ObserverProgram.Need(DirectRoles.Close(slot) || !result.AnchorAckPublished &&
            !result.EndByAnchorDeadline && result.AnchorUpperMs == -1);
        return result;
    }
}
