using System.Text.Json;
using Authentication.Core;

namespace Authentication.Windows;

internal static class WindowsDiagnostics
{
    internal static void Completed(SerializedResult result, bool telemetry, long entryTimestamp)
    {
        try
        {
            // Read only our own allowlisted projection. The diagnostic worker
            // receives fixed indications/event bytes, never the result or token.
            using var json = JsonDocument.Parse(result.Utf8Json);
            var outcome = json.RootElement.GetProperty("outcome").GetString();
            using var buffer = new MemoryStream();
            buffer.Write(outcome == "cancelled"
                ? "Authentication request cancelled.\n"u8 : "Authentication request completed.\n"u8);
            if (telemetry)
            {
                using var writer = new Utf8JsonWriter(buffer);
                writer.WriteStartObject();
                writer.WriteString("event", "request_completed");
                writer.WriteString("stage", "completion");
                writer.WriteString("outcome", outcome);
                writer.WriteNumber("elapsedMilliseconds", (long)Math.Max(0,
                    TimeProvider.System.GetElapsedTime(entryTimestamp).TotalMilliseconds));
                writer.WriteEndObject();
                writer.Flush();
                buffer.WriteByte((byte)'\n');
            }

            if (buffer.Length > 8192) return;
            var bytes = buffer.ToArray();
            new Thread(() =>
            {
                try { _ = WindowsStandardHandles.Write(WindowsStandardHandles.Error, bytes); }
                catch (Exception) { }
            }) { IsBackground = true }.Start();
        }
        catch (Exception)
        {
            // Optional diagnostics cannot alter authentication or process status.
        }
    }
}
