using System.Text.Json;
using Authentication.Core;

namespace Authentication.Windows;

// Request-local fixed categories only; never retain an exception or provider value.
internal enum WindowsMechanismFailure
{
    Unavailable, HostPlatform, HostWorkstation, HostThreadToken, HostLogon,
    HostSession, HostInputDesktop, DllSearch, BrokerUnavailable,
    BrokerPlatform, BrokerInitialization, RejectedWebUi
}

internal sealed class WindowsMechanismTrace
{
    private int first;
    internal WindowsMechanismFailure Failure => (WindowsMechanismFailure)Volatile.Read(ref first);
    internal void Record(WindowsMechanismFailure failure)
    {
        if (failure > WindowsMechanismFailure.Unavailable && failure <= WindowsMechanismFailure.RejectedWebUi)
            _ = Interlocked.CompareExchange(ref first, (int)failure, 0);
    }
}

internal static class WindowsDiagnostics
{
    internal static byte[] MechanismIndication(WindowsMechanismFailure failure) => failure switch
    {
        WindowsMechanismFailure.HostPlatform => "Mechanism unavailable at host_platform.\n"u8.ToArray(),
        WindowsMechanismFailure.HostWorkstation => "Mechanism unavailable at host_workstation.\n"u8.ToArray(),
        WindowsMechanismFailure.HostThreadToken => "Mechanism unavailable at host_thread_token.\n"u8.ToArray(),
        WindowsMechanismFailure.HostLogon => "Mechanism unavailable at host_logon.\n"u8.ToArray(),
        WindowsMechanismFailure.HostSession => "Mechanism unavailable at host_session.\n"u8.ToArray(),
        WindowsMechanismFailure.HostInputDesktop => "Mechanism unavailable at host_input_desktop.\n"u8.ToArray(),
        WindowsMechanismFailure.DllSearch => "Mechanism unavailable at dll_search.\n"u8.ToArray(),
        WindowsMechanismFailure.BrokerUnavailable => "Mechanism unavailable at broker_unavailable.\n"u8.ToArray(),
        WindowsMechanismFailure.BrokerPlatform => "Mechanism unavailable at broker_platform.\n"u8.ToArray(),
        WindowsMechanismFailure.BrokerInitialization => "Mechanism unavailable at broker_initialization.\n"u8.ToArray(),
        WindowsMechanismFailure.RejectedWebUi => "Mechanism unavailable at rejected_web_ui.\n"u8.ToArray(),
        _ => "Mechanism unavailable at unavailable.\n"u8.ToArray(),
    };

    internal static void Completed(SerializedResult result, bool telemetry, long entryTimestamp, WindowsMechanismTrace? trace = null)
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
            if (outcome == "mechanism_unavailable")
                buffer.Write(MechanismIndication(trace?.Failure ?? WindowsMechanismFailure.Unavailable));
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
