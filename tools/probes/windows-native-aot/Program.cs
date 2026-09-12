using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.NativeInterop;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

// Synthetic configuration only. Never construct Core or invoke an account/token API.
internal static partial class Program
{
    private const string SyntheticClient = "00000000-0000-0000-0000-000000000000";

    private static int Main()
    {
        bool aot = !RuntimeFeature.IsDynamicCodeSupported;
        bool restricted = SetDefaultDllDirectories(0x00000200 | 0x00000800);
        bool preloaded = GetModuleHandle("msalruntime.dll") != 0;
        bool builderCreated = false;
        string operation = "not_started";
        string exceptionType = "";
        int? nativeStatus = null;

        if (aot && restricted && !preloaded)
        {
            try
            {
                // This retains the selected MSAL/Broker construction path in the artifact.
                // Building a configuration does not execute its broker factory or acquire tokens.
                var application = PublicClientApplicationBuilder.Create(SyntheticClient)
                    .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows))
                    .Build();
                builderCreated = true;

                // The public wrapper enters the upstream API/x64 P/Invoke path. The
                // constructor allocates synthetic configuration without Core.Startup.
                // Disposal also follows upstream reference-counted native cleanup.
                using (var parameters = new AuthParameters(SyntheticClient, "https://example.invalid/"))
                {
                    operation = "configuration_created";
                    GC.KeepAlive(parameters);
                }
                GC.KeepAlive(application);
            }
            catch (Exception ex)
            {
                operation = "exception";
                exceptionType = ex.GetType().FullName ?? "unknown";
                if (ex is MsalRuntimeException runtimeException)
                    nativeStatus = (int)runtimeException.Status;
                if (ex is Win32Exception win32Exception)
                    nativeStatus = win32Exception.NativeErrorCode;
                // Do not emit messages, provider objects, stacks, or environment values.
            }
        }

        nint module = GetModuleHandle("msalruntime.dll");
        bool loaded = module != 0;
        bool applicationDirectory = loaded && IsApplicationModule(module);
        using (var writer = new Utf8JsonWriter(Console.OpenStandardOutput()))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("nativeAot", aot);
            writer.WriteBoolean("restrictedSearch", restricted);
            writer.WriteBoolean("unexpectedPreload", preloaded);
            writer.WriteBoolean("builderCreated", builderCreated);
            writer.WriteString("operation", operation);
            writer.WriteString("exceptionType", exceptionType);
            if (nativeStatus.HasValue) writer.WriteNumber("nativeStatus", nativeStatus.Value);
            writer.WriteBoolean("nativeModuleLoaded", loaded);
            writer.WriteBoolean("moduleInApplicationDirectory", applicationDirectory);
            writer.WriteEndObject();
        }
        return aot && restricted && !preloaded && builderCreated &&
            operation == "configuration_created" && applicationDirectory ? 0 : 1;
    }

    private static unsafe bool IsApplicationModule(nint module)
    {
        char* buffer = stackalloc char[32768];
        uint length = GetModuleFileName(module, buffer, 32768);
        if (length == 0 || length >= 32768) return false;
        string actual = new(buffer, 0, (int)length);
        string expected = Path.Combine(AppContext.BaseDirectory, "msalruntime.dll");
        return string.Equals(Path.GetFullPath(actual), Path.GetFullPath(expected),
            StringComparison.OrdinalIgnoreCase);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDefaultDllDirectories(uint directoryFlags);

    [LibraryImport("kernel32.dll", EntryPoint = "GetModuleHandleW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint GetModuleHandle(string moduleName);

    [LibraryImport("kernel32.dll", EntryPoint = "GetModuleFileNameW", SetLastError = true)]
    private static unsafe partial uint GetModuleFileName(nint module, char* fileName, uint size);
}
