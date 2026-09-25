// Inert source component: private QPC anchor and fixed zero-byte public handshake.
#nullable enable
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ConfidentialWsl;

internal static class AnchorHandshake
{
    internal const string RequestName = "close-anchor-request";
    internal const string AckName = "close-anchor-ack";
    internal static void RequireAbsent(PublicPlan plan)
    {
        foreach (string name in new[] { RequestName, RequestName + ".pending", AckName, AckName + ".pending" })
        {
            try { _ = File.GetAttributes(PublicRecords.PathOf(plan, name)); }
            catch (FileNotFoundException) { continue; }
            throw new SafeFailure(Fault.Admission);
        }
    }
    internal static bool RequestPresent(PublicPlan plan)
    {
        // The admission lease holds the fresh directory and ancestor no-replacement
        // boundary. OPEN_REPARSE_POINT and the held handle cover this fixed leaf.
        using SafeFileHandle file = Open(PublicRecords.PathOf(plan, RequestName),
            0x80000000, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (file.IsInvalid)
        {
            if (Marshal.GetLastWin32Error() == 2) return false;
            throw new SafeFailure(Fault.Admission);
        }
        Native.Check(GetFileType(file) == 1);
        Native.Check(GetFileInformationByHandle(file, out Info before));
        PrivateExpectation.Check((before.Attributes & (0x10u | 0x400u)) == 0 &&
            before.Links == 1 && before.SizeHigh == 0 && before.SizeLow == 0);
        byte[] probe = new byte[1];
        Native.Check(Native.ReadFile(file, probe, 1, out uint read, IntPtr.Zero));
        Native.Check(GetFileInformationByHandle(file, out Info after));
        PrivateExpectation.Check(read == 0 && Same(before, after));
        return true;
    }
    internal static void PublishAck(PublicPlan plan)
    {
        string final = PublicRecords.PathOf(plan, AckName), temporary = final + ".pending";
        using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            stream.Flush(true);
        File.Move(temporary, final, false);
    }
    internal static int ConservativeUpperMilliseconds(long anchor, long end)
    {
        long ticks = checked(end - anchor), frequency = Stopwatch.Frequency;
        if (frequency <= 0 || ticks < 2 || checked(ticks + 1) > frequency) return -1;
        long scaled = checked(checked(ticks + 1) * 1000);
        return checked((int)(checked(scaled + frequency - 1) / frequency));
    }
    private static bool Same(Info a, Info b) => a.Attributes == b.Attributes &&
        a.Volume == b.Volume && a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow &&
        a.SizeHigh == b.SizeHigh && a.SizeLow == b.SizeLow && a.Links == b.Links &&
        a.Created.Low == b.Created.Low && a.Created.High == b.Created.High &&
        a.Written.Low == b.Written.Low && a.Written.High == b.Written.High;
    [StructLayout(LayoutKind.Sequential)] private struct FileTime { internal uint Low, High; }
    [StructLayout(LayoutKind.Sequential)] private struct Info
    {
        internal uint Attributes;
        internal FileTime Created, Accessed, Written;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle Open(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
}
