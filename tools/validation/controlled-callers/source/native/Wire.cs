#nullable enable
using System;
using System.Buffers.Binary;

namespace ConfidentialNativeCaller;

internal static class Wire
{
    // Fixed binary safe-only worker frame, max 27 bytes; never a private result channel.
    internal static Fault? Failure(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 5 || !bytes[..4].SequenceEqual("NCF1"u8)) return null;
        PrivateRequest.Require(bytes[4] <= (byte)Fault.Expectation);
        return (Fault)bytes[4];
    }
    internal static byte[] Encode(SafeResult[] results)
    {
        byte[] bytes = new byte[5 + results.Length * 11];
        "NCW2"u8.CopyTo(bytes); bytes[4] = (byte)results.Length;
        for (int i = 0; i < results.Length; i++)
        {
            SafeResult r = results[i]; int p = 5 + i * 11;
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
        PrivateRequest.Require(bytes.Length == 5 + count * 11 && bytes[..4].SequenceEqual("NCW2"u8) && bytes[4] == count);
        var values = new SafeResult[count];
        for (int i = 0; i < count; i++)
        {
            int p = 5 + i * 11; byte flags = bytes[p + 2]; int elapsed = BinaryPrimitives.ReadInt32LittleEndian(bytes[(p + 3)..]);
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
            values[i] = new SafeResult { Outcome = outcome, Route = route, Passed = (flags & 1) != 0,
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
