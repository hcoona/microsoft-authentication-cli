#nullable enable
using System;
using System.IO;
using System.Text.Json;
namespace ConfidentialNativeCaller;
internal static class SafeReceipt
{
    internal static byte[] Project(PublicPlan plan, string slot, string nonce, bool reservation, SafeResult? result,
        bool passed, bool safeEof, bool jobZero, bool stopAttempted, bool stopSucceeded, int elapsedMilliseconds,
        Fault? firstFault = null)
    {
        using var memory = new MemoryStream();
        using (var json = new Utf8JsonWriter(memory))
        {
            json.WriteStartObject();
            json.WriteString("schema", "confidential-native-case-v1"); json.WriteString("slot", slot);
            json.WriteString("nonce", nonce); json.WriteString("hostRole", "native-windows");
            json.WriteString("productSha256", plan.ProductSha256); json.WriteString("callerSha256", plan.CallerSha256);
            json.WriteString("protocolSha256", plan.ProtocolSha256); json.WriteBoolean("reservation", reservation);
            json.WriteBoolean("passed", passed); json.WriteBoolean("safeWorkerEof", safeEof);
            json.WriteBoolean("scopedJobZero", jobZero); json.WriteBoolean("stopAttempted", stopAttempted);
            json.WriteBoolean("stopSucceeded", stopSucceeded); json.WriteBoolean("noExperimentLive", false);
            json.WriteString("outcome", result?.Outcome.ToString() ?? "Unknown");
            json.WriteString("firstFailure", firstFault?.ToString() ?? "None");
            json.WriteString("apiRoute", result?.Route.ToString() ?? "None");
            json.WriteBoolean("protocolValid", result?.ProtocolValid ?? false);
            json.WriteBoolean("productExitConsistent", result is not null);
            json.WriteNumber("productExitCode", result is null ? -1 : result.Outcome == Outcome.Success ? 0 : 1);
            json.WriteString("resultClass", reservation ? "reserved" : passed ? "expectation-passed" :
                stopAttempted ? "owned-stop" : result is not null ? "expectation-failed" : "caller-failed");
            json.WriteBoolean("metadataValid", result?.MetadataValid ?? false);
            json.WriteBoolean("persistenceUnconfirmed", result?.PersistenceUnconfirmed ?? false);
            json.WriteBoolean("persistenceFailed", result?.PersistenceFailed ?? false);
            json.WriteBoolean("writerClosedAfterLiveSample", result?.WriterClosedAfterLiveSample ?? false);
            json.WriteNumber("writerCloseToExitMilliseconds", result?.WriterCloseToExitMilliseconds ?? -1);
            json.WriteNumber("writerCloseToCompletionMilliseconds", result?.WriterCloseToCompletionMilliseconds ?? -1);
            json.WriteBoolean("pairProcessOverlapObserved", result?.PairProcessOverlapObserved ?? false);
            json.WriteString("nativeExitEvidence", result is not null && !stopAttempted ? "creation-handle-and-job" : "unavailable");
            json.WriteString("uiWitness", "not-supplied"); // API route never becomes a visible/noUI claim.
            json.WriteNumber("elapsedMilliseconds", elapsedMilliseconds);
            json.WriteNumber("productElapsedMilliseconds", result?.ElapsedMilliseconds ?? 0);
            json.WriteEndObject(); json.Flush();
        }
        memory.WriteByte(10); PrivateRequest.Require(memory.Length <= 4096);
        return memory.ToArray();
    }
    internal static void Persist(byte[] bytes, Action before, Func<Stream> createExclusive, Action<Stream> flushDurably)
    {
        before();
        using Stream file = createExclusive();
        file.Write(bytes); flushDurably(file);
        before();
    }
}
