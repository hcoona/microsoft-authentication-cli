#nullable enable
using System;
using System.Buffers.Binary;

namespace ConfidentialNativeCaller;

internal enum WorkerStage : byte
{
    PublicArguments = 1, RootAndDeadlines, OrdinaryEnvironment, PublicControl,
    CallerInventory, ProductInventory, PrivateDescriptor, PublicPlan, CreatedRole,
    PrivateRead, PrivateParse, PrivateValidation, BeforeProduct, ProductLifecycle, SafeOutput
}
internal enum WorkerFrameDisposition { Unavailable, Invalid, Validated }
internal readonly record struct WorkerFailure(Fault Fault, WorkerStage Stage, int PublicInputOrdinal);
internal readonly record struct WorkerFrame(WorkerFrameDisposition Disposition, WorkerFailure? Failure = null);
internal sealed class WorkerCheckpoint
{
    private WorkerStage stage = WorkerStage.PublicArguments;
    private int ordinal = -1;
    internal WorkerFailure? First { get; private set; }
    internal void At(WorkerStage next, int publicOrdinal = -1)
    { if (First is null) { stage = next; ordinal = publicOrdinal; } }
    internal void Capture(Exception caught) =>
        First ??= new(caught is SafeFailure safe ? safe.Fault : Fault.Native, stage, ordinal);
}

internal static class Wire
{
    // Fixed binary safe-only worker frames, max 29 bytes; never a private result channel.
    // NCW2 remains readable for retained/synthetic evidence; fresh frames use NCW3.
    internal static bool ValidWorkerFailure(WorkerFailure failure) =>
        (byte)failure.Fault <= (byte)Fault.Expectation &&
        (byte)failure.Stage is >= 1 and <= 15 &&
        (failure.PublicInputOrdinal == -1 ||
            (failure.Stage == WorkerStage.CallerInventory && failure.PublicInputOrdinal is >= 0 and <= 193) ||
            (failure.Stage == WorkerStage.ProductInventory && failure.PublicInputOrdinal is >= 194 and <= 196));
    internal static byte[] EncodeFailure(WorkerFailure failure)
    {
        PrivateRequest.Require(ValidWorkerFailure(failure));
        byte[] bytes = new byte[10];
        "NCF2"u8.CopyTo(bytes); bytes[4] = (byte)failure.Fault; bytes[5] = (byte)failure.Stage;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(6), failure.PublicInputOrdinal);
        return bytes;
    }
    internal static WorkerFrame InspectFailure(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0 || (bytes.Length == 5 && bytes[..4].SequenceEqual("NCF1"u8) && bytes[4] <= (byte)Fault.Expectation))
            return new(WorkerFrameDisposition.Unavailable);
        if (bytes.Length >= 5 && (bytes[..4].SequenceEqual("NCW2"u8) || bytes[..4].SequenceEqual("NCW3"u8)))
        {
            if (bytes[4] is not (1 or 2)) return new(WorkerFrameDisposition.Invalid);
            try { _ = Decode(bytes, bytes[4]); return new(WorkerFrameDisposition.Unavailable); }
            catch (SafeFailure) { return new(WorkerFrameDisposition.Invalid); }
        }
        if (bytes.Length != 10 || !bytes[..4].SequenceEqual("NCF2"u8))
            return new(WorkerFrameDisposition.Invalid);
        var failure = new WorkerFailure((Fault)bytes[4], (WorkerStage)bytes[5], BinaryPrimitives.ReadInt32LittleEndian(bytes[6..]));
        return ValidWorkerFailure(failure) ? new(WorkerFrameDisposition.Validated, failure) : new(WorkerFrameDisposition.Invalid);
    }
    internal static Fault? Failure(ReadOnlySpan<byte> bytes)
    {
        WorkerFrame frame = InspectFailure(bytes);
        if (frame.Failure is WorkerFailure failure) return failure.Fault;
        if (bytes.Length != 5 || !bytes[..4].SequenceEqual("NCF1"u8)) return null;
        PrivateRequest.Require(bytes[4] <= (byte)Fault.Expectation);
        return (Fault)bytes[4];
    }
    internal static byte[] Encode(SafeResult[] results)
    {
        byte[] bytes = new byte[5 + results.Length * 12];
        "NCW3"u8.CopyTo(bytes); bytes[4] = (byte)results.Length;
        for (int i = 0; i < results.Length; i++)
        {
            SafeResult r = results[i]; int p = 5 + i * 12;
            MechanismDiagnostic diagnostic = r.Outcome == Outcome.MechanismUnavailable
                ? r.MechanismDiagnostic == MechanismDiagnostic.NotApplicable ? MechanismDiagnostic.Unavailable : r.MechanismDiagnostic
                : MechanismDiagnostic.NotApplicable;
            PrivateRequest.Require(diagnostic <= MechanismDiagnostic.RejectedWebUi);
            bytes[p + 11] = (byte)diagnostic;
            bytes[p] = (byte)r.Outcome; bytes[p + 1] = (byte)r.Route;
            bytes[p + 2] = (byte)((r.Passed ? 1 : 0) | (r.MetadataValid ? 2 : 0) |
                (r.PersistenceUnconfirmed ? 4 : 0) | (r.PersistenceFailed ? 8 : 0) | (r.WriterClosedAfterLiveSample ? 16 : 0) |
                (r.ProtocolValid ? 32 : 0) | (r.PairProcessOverlapObserved ? 64 : 0));
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(p + 3), r.ElapsedMilliseconds);
            WriteDuration(bytes.AsSpan(p + 7), r.WriterCloseToExitMilliseconds);
            WriteDuration(bytes.AsSpan(p + 9), r.WriterCloseToCompletionMilliseconds);
        }
        return bytes;
    }
    internal static SafeResult[] Decode(ReadOnlySpan<byte> bytes, int count)
    {
        PrivateRequest.Require(bytes.Length >= 5 && count is 1 or 2 && bytes[4] == count);
        bool legacy = bytes[..4].SequenceEqual("NCW2"u8);
        int stride = legacy ? 11 : 12;
        PrivateRequest.Require((legacy || bytes[..4].SequenceEqual("NCW3"u8)) && bytes.Length == 5 + count * stride);
        var values = new SafeResult[count];
        for (int i = 0; i < count; i++)
        {
            int p = 5 + i * stride; byte flags = bytes[p + 2]; int elapsed = BinaryPrimitives.ReadInt32LittleEndian(bytes[(p + 3)..]);
            int exitAfterClose = ReadDuration(bytes[(p + 7)..]), completeAfterClose = ReadDuration(bytes[(p + 9)..]);
            PrivateRequest.Require(bytes[p] is >= 1 and <= 11 && bytes[p + 1] <= 2 && flags <= 127 && elapsed is >= 0 and <= 135000);
            bool closed = (flags & 16) != 0, overlap = (flags & 64) != 0;
            PrivateRequest.Require(closed ? exitAfterClose >= 0 && completeAfterClose >= exitAfterClose :
                exitAfterClose == -1 && completeAfterClose == -1);
            PrivateRequest.Require(count == 2 || !overlap);
            PrivateRequest.Require(count != 2 || (flags & 1) == 0 || overlap);
            Outcome outcome = (Outcome)bytes[p]; Route route = (Route)bytes[p + 1];
            PrivateRequest.Require((outcome == Outcome.Success) == (route != Route.None) &&
                (outcome == Outcome.Success) == ((flags & 2) != 0) && (flags & 32) != 0 &&
                (outcome == Outcome.Success || (flags & 12) == 0));
            MechanismDiagnostic diagnostic = legacy
                ? outcome == Outcome.MechanismUnavailable ? MechanismDiagnostic.Unavailable : MechanismDiagnostic.NotApplicable
                : (MechanismDiagnostic)bytes[p + 11];
            PrivateRequest.Require(diagnostic <= MechanismDiagnostic.RejectedWebUi &&
                (outcome == Outcome.MechanismUnavailable ? diagnostic != MechanismDiagnostic.NotApplicable : diagnostic == MechanismDiagnostic.NotApplicable));
            values[i] = new SafeResult { Outcome = outcome, Route = route, MechanismDiagnostic = diagnostic, Passed = (flags & 1) != 0,
                ProtocolValid = true, MetadataValid = (flags & 2) != 0,
                PersistenceUnconfirmed = (flags & 4) != 0, PersistenceFailed = (flags & 8) != 0,
                WriterClosedAfterLiveSample = closed, ElapsedMilliseconds = elapsed,
                WriterCloseToExitMilliseconds = exitAfterClose, WriterCloseToCompletionMilliseconds = completeAfterClose,
                PairProcessOverlapObserved = overlap };
        }
        PrivateRequest.Require(count != 2 || values[0].PairProcessOverlapObserved == values[1].PairProcessOverlapObserved);
        return values;
    }
    private static void WriteDuration(Span<byte> destination, int value)
    {
        PrivateRequest.Require(value is >= -1 and <= 1000);
        BinaryPrimitives.WriteUInt16LittleEndian(destination, value < 0 ? ushort.MaxValue : (ushort)value);
    }
    private static int ReadDuration(ReadOnlySpan<byte> source)
    {
        ushort value = BinaryPrimitives.ReadUInt16LittleEndian(source);
        PrivateRequest.Require(value <= 1000 || value == ushort.MaxValue);
        return value == ushort.MaxValue ? -1 : value;
    }
}
