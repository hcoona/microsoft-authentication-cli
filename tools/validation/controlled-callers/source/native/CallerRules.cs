// Shared production decisions. This file has no native calls, clocks, threads, or file discovery.
#nullable enable
using System;
using System.IO;
namespace ConfidentialNativeCaller;
internal enum ReadDecision { Continue, Data, Eof, Fail }
internal readonly record struct FrameDecision(SafeResult[]? Results, Fault? FirstFault, bool Passed);
internal static class CallerRules
{
    internal static uint BeginRead(int limit, int count, ref int calls)
    {
        if (++calls > limit + 1024) throw new SafeFailure(Fault.Capture);
        return (uint)Math.Min(4096, limit - count + 1);
    }
    internal static ReadDecision ReadStep(int limit, int count, bool succeeded, uint read, int error)
    {
        if (!succeeded) return error == 109 ? ReadDecision.Eof : ReadDecision.Fail;
        if (read == 0) return ReadDecision.Continue;
        return read > limit - count ? ReadDecision.Fail : ReadDecision.Data;
    }
    internal static void Claim(ref bool attempted, Fault fault)
    {
        if (attempted) throw new SafeFailure(fault);
        attempted = true;
    }
    internal static void ResumeResult(uint priorCount)
    { if (priorCount != 1) throw new SafeFailure(Fault.Native); }
    internal static long Add(long start, int milliseconds, long frequency) =>
        checked(start + frequency * milliseconds / 1000);
    internal static long CancellationEnd(long originalDeadline, long closeStarted, long frequency) =>
        Math.Min(originalDeadline, Add(closeStarted, 1000, frequency));
    internal static long EffectiveDeadline(long originalDeadline, long? cancellationEnd) =>
        Math.Min(originalDeadline, cancellationEnd ?? originalDeadline);
    internal static void Before(long now, long deadline)
    { if (now >= deadline) throw new SafeFailure(Fault.Deadline); }
    internal static bool ProductComplete(bool exit, bool outDone, bool outEof, bool errDone, bool errEof) =>
        exit && outDone && outEof && errDone && errEof;
    internal static bool SupervisorComplete(bool exit, bool jobZero, bool outDone, bool outEof, bool errDone, bool errEof) =>
        jobZero && ProductComplete(exit, outDone, outEof, errDone, errEof);
    internal static bool PairPass(bool paired, bool positiveOverlap) => !paired || positiveOverlap;
    internal static bool TerminalMayPass(bool expectationPassed, bool stopAttempted) => expectationPassed && !stopAttempted;
    internal static void WriteFrame(ref bool attempted, byte[] safe, Func<Stream> open)
    {
        Claim(ref attempted, Fault.Capture);
        using Stream stdout = open();
        stdout.Write(safe); stdout.Flush();
    }
    internal static FrameDecision DecideFrame(ReadOnlySpan<byte> bytes, int slots, uint total, uint exit, int errorBytes)
    {
        PrivateRequest.Require(slots is 1 or 2 && errorBytes == 0 && total >= 1 && total <= slots + 1);
        Fault? first = Wire.Failure(bytes);
        if (first is not null) return new(null, first, false);
        PrivateRequest.Require(total == slots + 1);
        SafeResult[] results = Wire.Decode(bytes, slots);
        bool all = true;
        foreach (SafeResult result in results) all &= result.Passed;
        bool passed = exit == 0 && all;
        return new(results, passed ? null : all ? Fault.Native : Fault.Expectation, passed);
    }
}
