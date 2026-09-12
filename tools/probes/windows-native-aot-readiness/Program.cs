using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Client.NativeInterop;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

// Synthetic allocation/cleanup only. The preserved provider surface is never invoked.
internal static partial class Program
{
    private const string Client = "00000000-0000-0000-0000-000000000000";
    private static int firstChanceCount;

    [DynamicDependency(nameof(CompileOnlyProviderSurface))]
    private static int Main()
    {
        bool aot = !RuntimeFeature.IsDynamicCodeSupported;
        bool restricted = SetDefaultDllDirectories(0x200 | 0x800);
        bool preloaded = GetModuleHandle("msalruntime.dll") != 0;
        bool selfCheck = false, builderCreated = false, allocated = false;
        bool exportsPresent = false, disposed = false, disposedTwice = false;
        int cleanupExceptions = -1;
        string exceptionType = "", innerExceptionType = "";
        AppDomain.CurrentDomain.FirstChanceException += CountException;
        try
        {
            // Validate this observation mechanism on the actual native binary.
            try { throw new InvalidOperationException(); }
            catch (InvalidOperationException) { }
            selfCheck = Volatile.Read(ref firstChanceCount) == 1;
            if (aot && restricted && !preloaded && selfCheck)
            {
                var application = PublicClientApplicationBuilder.Create(Client)
                    .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows))
                    .Build();
                builderCreated = true;
                var parameters = new AuthParameters(Client, "https://example.invalid/");
                allocated = true;
                nint module = GetModuleHandle("msalruntime.dll");
                exportsPresent = module != 0 &&
                    NativeLibrary.TryGetExport(module, "MSALRUNTIME_ReleaseAuthParameters", out _) &&
                    NativeLibrary.TryGetExport(module, "MSALRUNTIME_Shutdown", out _);
                int before = Volatile.Read(ref firstChanceCount);
                try
                {
                    parameters.Dispose();
                    disposed = true;
                    parameters.Dispose();
                    disposedTwice = true;
                }
                finally { cleanupExceptions = Volatile.Read(ref firstChanceCount) - before; }
                GC.KeepAlive(parameters);
                GC.KeepAlive(application);
            }
        }
        catch (Exception ex)
        {
            exceptionType = ex.GetType().FullName ?? "unknown";
            innerExceptionType = ex.InnerException?.GetType().FullName ?? "";
        }
        finally { AppDomain.CurrentDomain.FirstChanceException -= CountException; }

        nint loadedModule = GetModuleHandle("msalruntime.dll");
        bool loaded = loadedModule != 0;
        bool appDirectory = loaded && IsApplicationModule(loadedModule);
        using var writer = new Utf8JsonWriter(Console.OpenStandardOutput());
        writer.WriteStartObject();
        writer.WriteBoolean("nativeAot", aot);
        writer.WriteBoolean("restrictedSearch", restricted);
        writer.WriteBoolean("unexpectedPreload", preloaded);
        writer.WriteBoolean("firstChanceSelfCheck", selfCheck);
        writer.WriteBoolean("builderCreated", builderCreated);
        writer.WriteBoolean("allocated", allocated);
        writer.WriteBoolean("cleanupExportsPresent", exportsPresent);
        writer.WriteBoolean("disposeReturned", disposed);
        writer.WriteBoolean("secondDisposeReturned", disposedTwice);
        writer.WriteNumber("cleanupFirstChanceExceptions", cleanupExceptions);
        writer.WriteString("exceptionType", exceptionType);
        writer.WriteString("innerExceptionType", innerExceptionType);
        writer.WriteBoolean("nativeModuleLoaded", loaded);
        writer.WriteBoolean("moduleInApplicationDirectory", appDirectory);
        writer.WriteEndObject();
        return aot && restricted && !preloaded && selfCheck && builderCreated && allocated &&
            exportsPresent && disposed && disposedTwice && cleanupExceptions == 0 &&
            exceptionType == "" && appDirectory ? 0 : 1;
    }

    private static void CountException(object? sender, FirstChanceExceptionEventArgs args)
        => Interlocked.Increment(ref firstChanceCount);

    // Compilation root only, with no runtime caller, callback, reflection invocation,
    // argument switch, or delegate creation. This is not an authentication experiment.
    private static void CompileOnlyProviderSurface(PublicClientApplication application,
        IAccount account, string[] scopes, string tenant, string email, string claims,
        nint parent, CancellationToken cancellation)
    {
        _ = application.IsBrokerAvailable();
        _ = application.GetAccountsAsync(cancellation);
        _ = application.AcquireTokenSilent(scopes, account).WithTenantId(tenant)
            .WithClaims(claims).ExecuteAsync(cancellation);
        _ = application.AcquireTokenInteractive(scopes).WithAccount(account)
            .WithLoginHint(email).WithTenantId(tenant).WithClaims(claims)
            .WithParentActivityOrWindow(parent).WithCustomWebUi(new RejectBrowser())
            .ExecuteAsync(cancellation);
    }

    private sealed class RejectBrowser : ICustomWebUi
    {
        public Task<Uri> AcquireAuthorizationCodeAsync(Uri authorizationUri, Uri redirectUri,
            CancellationToken cancellationToken) => throw new InvalidOperationException();
    }

    private static unsafe bool IsApplicationModule(nint module)
    {
        char* buffer = stackalloc char[32768];
        uint length = GetModuleFileName(module, buffer, 32768);
        if (length == 0 || length >= 32768) return false;
        string actual = new(buffer, 0, (int)length);
        return string.Equals(Path.GetFullPath(actual),
            Path.Combine(AppContext.BaseDirectory, "msalruntime.dll"), StringComparison.OrdinalIgnoreCase);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDefaultDllDirectories(uint directoryFlags);

    [LibraryImport("kernel32.dll", EntryPoint = "GetModuleHandleW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint GetModuleHandle(string moduleName);

    [LibraryImport("kernel32.dll", EntryPoint = "GetModuleFileNameW", SetLastError = true)]
    private static unsafe partial uint GetModuleFileName(nint module, char* fileName, uint size);
}
