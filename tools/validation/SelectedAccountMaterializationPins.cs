// Public-file preparation only. Native checks follow FixtureNativePins; C# 5
// syntax allows the existing Windows PowerShell 5.1 Add-Type compiler.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class SelectedAccountFileIdentity
{
    public uint volume, attributes, links;
    public ulong index;
    public long created, modified, changed, length;
    public bool Same(SelectedAccountFileIdentity other)
    {
        return other != null && volume == other.volume && index == other.index &&
            attributes == other.attributes && links == other.links && created == other.created &&
            modified == other.modified && changed == other.changed && length == other.length;
    }
}

public sealed class SelectedAccountHeldFile
{
    internal FileStream Stream;
    public string path, sha256;
    public SelectedAccountFileIdentity identity;
    public SelectedAccountFileIdentity sourceIdentity;
}

public sealed class SelectedAccountMaterializationPins : IDisposable
{
    private readonly Action before;
    private readonly Dictionary<string, SafeFileHandle> directories =
        new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
    private readonly List<IDisposable> owned = new List<IDisposable>();
    private readonly List<SelectedAccountHeldFile> files = new List<SelectedAccountHeldFile>();
    public long requestedReadBytes, writtenBytes, reads, writes, opens, metadata;

    public SelectedAccountMaterializationPins(Action check) { before = check; }
    private void Need(bool value) { if (!value) throw new InvalidOperationException("Public preparation refused."); }
    private void Tick() { before(); Need(owned.Count < 512); }
    private void Canonical(string path)
    {
        Need(path.Length >= 3 && path.Length <= 1024 && path.StartsWith(@"C:\", StringComparison.Ordinal) &&
            !path.Contains('/') && !path.Substring(2).Contains(':') && !path.Any(char.IsControl) &&
            Path.GetFullPath(path) == path);
        foreach (string part in path.Substring(3).Split('\\'))
            Need(part.Length > 0 && part != "." && part != ".." && !part.EndsWith(".") && !part.EndsWith(" "));
    }
    private SafeFileHandle Open(string path, uint access, uint share, uint disposition, uint flags)
    {
        Tick(); Need(++opens <= 4096);
        SafeFileHandle handle = CreateFile(path, access, share, IntPtr.Zero, disposition, flags, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); Need(false); }
        return handle;
    }
    private Info Information(SafeFileHandle handle)
    {
        Tick(); Need(++metadata <= 32768);
        Info info; Need(GetFileInformationByHandle(handle, out info)); return info;
    }
    private SelectedAccountFileIdentity Snapshot(SafeFileHandle handle)
    {
        Info info = Information(handle); Basic basic = new Basic();
        Tick(); metadata += 2; Need(metadata <= 32768);
        Need(GetFileType(handle) == 1 && (info.Attributes & 0x410) == 0 && info.Links == 1 &&
            GetFileInformationByHandleEx(handle, 0, out basic, (uint)Marshal.SizeOf(typeof(Basic))));
        Need(basic.Attributes == info.Attributes);
        return new SelectedAccountFileIdentity { volume = info.Volume,
            index = ((ulong)info.IndexHigh << 32) | info.IndexLow, attributes = basic.Attributes,
            created = basic.Created, modified = basic.Modified, changed = basic.Changed,
            length = checked((long)(((ulong)info.SizeHigh << 32) | info.SizeLow)), links = info.Links };
    }
    private void Name(SafeFileHandle handle, string path)
    {
        Tick(); Need(++metadata <= 32768);
        StringBuilder name = new StringBuilder(2048);
        uint count = GetFinalPathNameByHandle(handle, name, (uint)name.Capacity, 0);
        Need(count > 0 && count < name.Capacity &&
            string.Equals(name.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase));
    }
    public void HoldDirectory(string path)
    {
        Tick(); if (directories.ContainsKey(path)) return;
        if (path != @"C:\") Canonical(path);
        string parent = path == @"C:\" ? null : Path.GetDirectoryName(path);
        if (parent != null) HoldDirectory(parent);
        Need(directories.Count < 128);
        SafeFileHandle handle = Open(path, 0x80, 3, 3, 0x02200000);
        try
        {
            Info info = Information(handle); Need(GetFileType(handle) == 1 && (info.Attributes & 0x410) == 0x10);
            Name(handle, path); Tick(); directories.Add(path, handle); owned.Add(handle);
        }
        catch { handle.Dispose(); throw; }
    }
    public void CreateDirectoryExclusive(string path)
    {
        Canonical(path); HoldDirectory(Path.GetDirectoryName(path)); Tick();
        Need(CreateDirectory(path, IntPtr.Zero)); HoldDirectory(path);
    }
    private int Read(FileStream stream, byte[] buffer, int count)
    {
        Tick(); Need(++reads <= 32768); requestedReadBytes += count;
        Need(requestedReadBytes <= 469762048); return stream.Read(buffer, 0, count);
    }
    private string Hash(FileStream stream, long length)
    {
        stream.Position = 0; byte[] buffer = new byte[65536]; long total = 0;
        using (SHA256 hash = SHA256.Create())
        {
            while (total < length)
            {
                int count = Read(stream, buffer, (int)Math.Min(buffer.Length, length - total));
                Need(count > 0); hash.TransformBlock(buffer, 0, count, buffer, 0); total += count;
            }
            Need(Read(stream, buffer, 1) == 0); hash.TransformFinalBlock(new byte[0], 0, 0);
            Array.Clear(buffer, 0, buffer.Length);
            return BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
        }
    }
    private void Stable(SelectedAccountHeldFile file)
    {
        Need(Snapshot(file.Stream.SafeFileHandle).Same(file.identity)); Name(file.Stream.SafeFileHandle, file.path);
        using (SafeFileHandle named = Open(file.path, 0x80, 1, 3, 0x00200000))
        { Name(named, file.path); Need(Snapshot(named).Same(file.identity)); }
    }
    public SelectedAccountHeldFile Pin(string path, long length, string hash)
    {
        Canonical(path); Need(length > 0 && length <= 67108864 && hash.Length == 64 &&
            hash.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
        HoldDirectory(Path.GetDirectoryName(path));
        SafeFileHandle handle = Open(path, 0x80000000, 1, 3, 0x00200000); FileStream stream = null;
        try
        {
            SelectedAccountFileIdentity identity = Snapshot(handle); Need(identity.length == length); Name(handle, path);
            stream = new FileStream(handle, FileAccess.Read, 65536, false); Need(Hash(stream, length) == hash);
            SelectedAccountHeldFile file = new SelectedAccountHeldFile { Stream = stream, path = path,
                sha256 = hash, identity = identity };
            Stable(file); stream.Position = 0; owned.Add(stream); files.Add(file); return file;
        }
        catch { if (stream != null) stream.Dispose(); else handle.Dispose(); throw; }
    }
    public SelectedAccountHeldFile Copy(string source, string target, long length, string hash)
    {
        SelectedAccountHeldFile input = Pin(source, length, hash);
        Canonical(target); HoldDirectory(Path.GetDirectoryName(target));
        SelectedAccountFileIdentity original;
        using (SafeFileHandle handle = Open(target, 0xc0000000, 1, 1, 0x00200000))
        using (FileStream writer = new FileStream(handle, FileAccess.ReadWrite, 65536, false))
        {
            original = Snapshot(handle); Need(original.length == 0); Name(handle, target);
            input.Stream.Position = 0; byte[] buffer = new byte[65536]; long total = 0;
            try
            {
                while (total < length)
                {
                    int count = Read(input.Stream, buffer, (int)Math.Min(buffer.Length, length - total)); Need(count > 0);
                    Tick(); Need(++writes <= 32768); writtenBytes += count; Need(writtenBytes <= 134217728);
                    writer.Write(buffer, 0, count); total += count;
                }
                Need(Read(input.Stream, buffer, 1) == 0); writer.Flush(true); Stable(input); Tick();
            }
            finally { Array.Clear(buffer, 0, buffer.Length); }
        }
        SelectedAccountHeldFile output = Pin(target, length, hash);
        Need(output.identity.volume == original.volume && output.identity.index == original.index &&
            output.identity.created == original.created);
        output.sourceIdentity = input.identity; Tick(); return output;
    }
    public byte[] ReadControl(SelectedAccountHeldFile file, int maximum)
    {
        Need(file.identity.length <= maximum); Stable(file); file.Stream.Position = 0;
        byte[] result = new byte[(int)file.identity.length], buffer = new byte[65536]; int offset = 0;
        while (offset < result.Length)
        {
            int count = Read(file.Stream, buffer, Math.Min(buffer.Length, result.Length - offset)); Need(count > 0);
            Buffer.BlockCopy(buffer, 0, result, offset, count); offset += count;
        }
        Need(Read(file.Stream, buffer, 1) == 0); Array.Clear(buffer, 0, buffer.Length); Stable(file); return result;
    }
    public void CheckAll() { foreach (SelectedAccountHeldFile file in files) Stable(file); Tick(); }
    public void Dispose()
    {
        Exception failure = null;
        // Pop before closing: each detached resource receives one close attempt.
        while (owned.Count > 0)
        {
            int last = owned.Count - 1; IDisposable resource = owned[last]; owned.RemoveAt(last);
            try { resource.Dispose(); } catch (Exception error) { if (failure == null) failure = error; }
        }
        files.Clear(); directories.Clear(); if (failure != null) throw failure;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Info
    { internal uint Attributes, CreatedLow, CreatedHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume,
        SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [StructLayout(LayoutKind.Sequential)] private struct Basic
    { internal long Created, Accessed, Modified, Changed; internal uint Attributes; }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateDirectory(string path, IntPtr security);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, out Basic info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint GetFileType(SafeFileHandle handle);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder name, uint length, uint flags);
}
