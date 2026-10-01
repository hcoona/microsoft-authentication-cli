// Inert, read-only reconciliation of exactly two previously recorded process incarnations.
// This validation executable has no account, token, image, child or termination API.
using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

internal static class RetainedClosureObserver
{
    private static readonly bool ExecutionAdmitted = false;
    private static readonly ulong Started = GetTickCount64();
    private static long Expires;
    private const uint Rights = 0x101000u; // QUERY_LIMITED_INFORMATION | SYNCHRONIZE
    private const uint InvalidClientId = 0xc000000bu;

    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted) return 125;
        try
        {
            if (args.Length != 4 || args[0] != "--observe" ||
                args[1] != @"C:\Temp\azureauth-windows-slice-108\closure-observer-0181" ||
                !Regex.IsMatch(args[2], @"\A[0-9a-f]{64}\z") ||
                !Regex.IsMatch(args[3], @"\A[1-9][0-9]{16,18}\z")) return 101;
            Expires = long.Parse(args[3], CultureInfo.InvariantCulture);
            long remaining = Expires - DateTime.UtcNow.ToFileTimeUtc();
            if (remaining <= 0 || remaining > 200000000L) return 102;
            string root = args[1];
            Direct(root);
            using (SafeFileHandle directory = DirectoryHandle(root))
            using (FileStream selector = Pin(Path.Combine(root, "selector.txt"), args[2], 4096))
            {
                string[] fields = Text(selector).Split('\n');
                if (fields.Length != 10 || fields[0] != "azureauth-retained-closure-v1" ||
                    !Regex.IsMatch(fields[1], @"\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z") ||
                    !Regex.IsMatch(fields[2], @"\A[0-9a-f]{64}\z") ||
                    !Regex.IsMatch(fields[7], @"\A[0-9a-f]{64}\z") ||
                    fields[8] != "END" || fields[9] != "") return 103;
                uint first = Pid(fields[3]), second = Pid(fields[5]);
                long firstCreation = Creation(fields[4]), secondCreation = Creation(fields[6]);
                if (first == second) return 104;
                using (FileStream image = Pin(Path.Combine(root, "RetainedClosureObserver.exe"), fields[7], 2097152))
                {
                    // Exclusive result creation precedes both queries; an occupied output stops here.
                    string outputPath = Path.Combine(root, "native-result.txt");
                    Direct(root);
                    using (FileStream output = new FileStream(outputPath, FileMode.CreateNew,
                        FileAccess.Write, FileShare.Read))
                    {
                        string firstRow = Observe(first, firstCreation);
                        string secondRow = Observe(second, secondCreation);
                        Budget();
                        byte[] bytes = Encoding.ASCII.GetBytes("azureauth-retained-closure-result-v1\n" +
                            fields[1] + "\n" + args[2] + "\n" + firstRow + "\n" + secondRow + "\nEND\n");
                        if (bytes.Length > 4096) throw new InvalidOperationException();
                        output.Write(bytes, 0, bytes.Length);
                        output.Flush(true);
                        Budget();
                    }
                }
            }
            Budget();
            return 0; // Complete observation, not a claim that either subject is closed.
        }
        catch { return 1; } // No exception message, input content or stream diagnostics.
    }

    private static string Observe(uint pid, long expected)
    {
        Budget();
        var attributes = new ObjectAttributes();
        attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
        var client = new ClientId();
        client.Process = new IntPtr((long)pid);
        IntPtr raw = IntPtr.Zero;
        // One native open only. INVALID_CID is distinct from invalid access arguments.
        uint status = NtOpenProcess(ref raw, Rights, ref attributes, ref client);
        using (var handle = new SafeFileHandle(raw, true))
        {
            Budget();
            if (status != 0)
                return Row(status == InvalidClientId && handle.IsInvalid ? 0 : 4,
                    status, 0, -1, -1, 1, 0);
            if (handle.IsInvalid) return Row(4, status, 0, -1, -1, 1, 0);
            long created, exited, kernel, user;
            bool times = GetProcessTimes(handle, out created, out exited, out kernel, out user);
            int error = times ? 0 : Marshal.GetLastWin32Error();
            Budget();
            if (!times || created <= 0) return Row(4, status, created, -1, -1, 2, error);
            uint wait = WaitForSingleObject(handle, 0);
            error = wait == uint.MaxValue ? Marshal.GetLastWin32Error() : 0;
            Budget();
            if (wait != 0 && wait != 258) return Row(4, status, created, wait, -1, 3, error);
            long exit = -1;
            if (wait == 0)
            {
                uint code;
                bool sampled = GetExitCodeProcess(handle, out code);
                error = sampled ? 0 : Marshal.GetLastWin32Error();
                Budget();
                if (!sampled) return Row(4, status, created, wait, -1, 4, error);
                exit = code;
            }
            // 0 absent; 1 reused; 2 matching exited; 3 matching live; 4 query failure.
            return Row(created != expected ? 1 : wait == 0 ? 2 : 3,
                status, created, wait, exit, 0, 0);
        }
    }

    private static string Row(int state, uint status, long created, long wait,
        long exit, int stage, int error)
    {
        return String.Join(",", new[] { state.ToString(CultureInfo.InvariantCulture),
            status.ToString(CultureInfo.InvariantCulture), created.ToString(CultureInfo.InvariantCulture),
            wait.ToString(CultureInfo.InvariantCulture), exit.ToString(CultureInfo.InvariantCulture),
            stage.ToString(CultureInfo.InvariantCulture), error.ToString(CultureInfo.InvariantCulture) });
    }
    private static uint Pid(string text)
    {
        if (!Regex.IsMatch(text, @"\A[1-9][0-9]{0,9}\z")) throw new InvalidOperationException();
        uint value = uint.Parse(text, CultureInfo.InvariantCulture);
        if (value <= 4) throw new InvalidOperationException();
        return value;
    }
    private static long Creation(string text)
    {
        if (!Regex.IsMatch(text, @"\A[1-9][0-9]{16,18}\z")) throw new InvalidOperationException();
        long value = long.Parse(text, CultureInfo.InvariantCulture);
        DateTime.FromFileTimeUtc(value);
        return value;
    }
    private static void Budget()
    {
        if (GetTickCount64() - Started >= 20000 || DateTime.UtcNow.ToFileTimeUtc() >= Expires)
            throw new TimeoutException();
    }
    private static void Direct(string path)
    {
        for (string current = path; current != null; current = Path.GetDirectoryName(current))
        {
            Budget();
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException();
        }
    }
    private static SafeFileHandle DirectoryHandle(string root)
    {
        SafeFileHandle handle = CreateFile(root, 0, 3, IntPtr.Zero, 3, 0x02200000u, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new InvalidOperationException(); }
        return handle;
    }
    private static FileStream Pin(string path, string expected, int maximum)
    {
        Direct(path);
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            Budget();
            if (file.Length <= 0 || file.Length > maximum) throw new InvalidOperationException();
            using (SHA256 hash = SHA256.Create())
                if (BitConverter.ToString(hash.ComputeHash(file)).Replace("-", "").ToLowerInvariant() != expected)
                    throw new InvalidOperationException();
            Budget();
            return file;
        }
        catch { file.Dispose(); throw; }
    }
    private static string Text(FileStream file)
    {
        file.Position = 0;
        byte[] bytes = new byte[checked((int)file.Length)];
        int position = 0;
        while (position < bytes.Length)
        {
            Budget();
            int read = file.Read(bytes, position, bytes.Length - position);
            if (read == 0) throw new InvalidOperationException();
            position += read;
        }
        if (file.ReadByte() != -1) throw new InvalidOperationException();
        foreach (byte value in bytes)
            if (value > 127 || value == 0 || value == 13) throw new InvalidOperationException();
        return Encoding.ASCII.GetString(bytes);
    }
    [StructLayout(LayoutKind.Sequential)] private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ClientId { public IntPtr Process, Thread; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateFileW", SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("ntdll.dll", ExactSpelling = true)] private static extern uint NtOpenProcess(
        ref IntPtr process, uint access, ref ObjectAttributes attributes, ref ClientId client);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(
        SafeFileHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(
        SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(
        SafeFileHandle process, out uint code);
    [DllImport("kernel32.dll")] private static extern ulong GetTickCount64();
}
