// Inert source: one constructed current-user profile environment for the worker edge.
#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ConfidentialNativeCaller;

internal sealed class CurrentUserEnvironment : IDisposable
{
    internal const int MaximumUtf16Units = 32768, MaximumEntries = 1024;
    private IntPtr block;
    internal IntPtr Block => block != IntPtr.Zero ? block : throw new SafeFailure(Fault.Admission);
    private CurrentUserEnvironment(IntPtr value) { block = value; }

    internal static CurrentUserEnvironment Create(long workEnd)
    {
        Before(workEnd);
        // Only this process's primary token is opened. No alternate identity,
        // impersonation, profile loading, repair, environment export, or fallback.
        bool opened = OpenProcessToken(GetCurrentProcess(), 0x000A, out SafeFileHandle token);
        using (token)
        {
            Native.Check(opened && !token.IsInvalid);
            Before(workEnd);
            Native.Check(CreateEnvironmentBlock(out IntPtr value, token, false));
            Native.Check(value != IntPtr.Zero);
            var environment = new CurrentUserEnvironment(value);
            try
            {
                environment.Validate(workEnd);
                Before(workEnd);
                return environment;
            }
            catch { environment.Dispose(); throw; }
        }
    }

    private static void Before(long workEnd) => CallerRules.Before(Stopwatch.GetTimestamp(), workEnd);
    private void Validate(long workEnd)
    {
        // The trusted userenv API returns a valid double-NUL block but no length.
        // Bound all inspection and allocation; do not scan beyond this refusal cap.
        char[] characters = new char[MaximumUtf16Units];
        try
        {
            int end = -1;
            for (int offset = 0; offset < characters.Length; offset++)
            {
                if ((offset & 255) == 0) Before(workEnd);
                characters[offset] = (char)(ushort)Marshal.ReadInt16(Block, checked(offset * 2));
                if (offset > 0 && characters[offset] == '\0' && characters[offset - 1] == '\0')
                { end = offset; break; }
            }
            PrivateRequest.Require(end > 1);
            var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string? profile = null, temporary = null, alternateTemporary = null;
            int start = 0, entries = 0;
            for (int offset = 0; offset < end; offset++)
            {
                if ((offset & 255) == 0) Before(workEnd);
                if (characters[offset] != '\0') continue;
                PrivateRequest.Require(++entries <= MaximumEntries && offset > start);
                string entry = new(characters, start, offset - start);
                int equal = entry.IndexOf('=');
                PrivateRequest.Require(equal is > 0 and <= 1024);
                string key = entry[..equal], value = entry[(equal + 1)..];
                PrivateRequest.Require(!key.Any(char.IsControl) && keys.Add(key) && !RejectsRuntimeKey(key));
                if (key.Equals("USERPROFILE", StringComparison.OrdinalIgnoreCase)) profile = value;
                if (key.Equals("TEMP", StringComparison.OrdinalIgnoreCase)) temporary = value;
                if (key.Equals("TMP", StringComparison.OrdinalIgnoreCase)) alternateTemporary = value;
                start = offset + 1;
            }
            PrivateRequest.Require(start == end && entries > 0);
            // CreateEnvironmentBlock documents user profile variables only for a
            // loaded profile. Missing/invalid values fail; no LoadUserProfile repair.
            // This does not prove designated identity/session, WAM health or account state.
            OrdinaryPath(profile); OrdinaryPath(temporary); OrdinaryPath(alternateTemporary);
            Before(workEnd);
        }
        finally { Array.Clear(characters); }
    }

    internal static bool RejectsRuntimeKey(string key)
    {
        if (key.Equals("DOTNET_CLI_TELEMETRY_OPTOUT", StringComparison.OrdinalIgnoreCase)) return false;
        return key.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase) ||
            key.StartsWith("COMPlus_", StringComparison.OrdinalIgnoreCase) ||
            key.StartsWith("CORECLR_", StringComparison.OrdinalIgnoreCase) ||
            key.StartsWith("COREHOST_", StringComparison.OrdinalIgnoreCase) ||
            key.StartsWith("COR_", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("APP_PATHS", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("APP_NI_PATHS", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("APP_CONTEXT_BASE_DIRECTORY", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("NATIVE_DLL_SEARCH_DIRECTORIES", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("TRUSTED_PLATFORM_ASSEMBLIES", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("PLATFORM_RESOURCE_ROOTS", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("PROBING_DIRECTORIES", StringComparison.OrdinalIgnoreCase);
    }

    private static void OrdinaryPath(string? value)
    {
        PrivateRequest.Require(value is not null && value.Length is >= 3 and <= 32766 &&
            char.IsAsciiLetter(value[0]) && value[1] == ':' && value[2] == '\\' &&
            !value.Any(char.IsControl) && !value.Contains('/') && !value[2..].Contains(':') &&
            !value.Split('\\').Any(part => part is "." or "..") &&
            !value.StartsWith(@"C:\Temp\azureauth-windows-slice-108", StringComparison.OrdinalIgnoreCase));
    }

    public void Dispose()
    {
        if (block == IntPtr.Zero) return;
        IntPtr owned = block; block = IntPtr.Zero;
        Native.Check(DestroyEnvironmentBlock(owned));
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeFileHandle token);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("userenv.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, SafeFileHandle token,
        [MarshalAs(UnmanagedType.Bool)] bool inherit);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("userenv.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);
}
