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
    // Copy outputs alias the stream-owned handle without invoking its flushing accessor.
    internal SafeFileHandle OutputObservationHandle;
    public string path, sha256;
    public SelectedAccountFileIdentity identity;
    public SelectedAccountFileIdentity sourceIdentity;
    // Retain both establishment observations; identity is the prospective sealed baseline.
    internal SelectedAccountFileIdentity outputInitialIdentity, outputFirstReadIdentity, outputFirstNamedIdentity;
}

public sealed class SelectedAccountMaterializationPins : IDisposable
{
    private readonly Action before;
    private readonly Dictionary<string, SafeFileHandle> directories =
        new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
    private readonly List<IDisposable> owned = new List<IDisposable>();
    private readonly List<SelectedAccountHeldFile> files = new List<SelectedAccountHeldFile>();
    public long requestedReadBytes, writtenBytes, reads, writes, opens, metadata;
    // Fixed numeric context only. Freeze the first fault before any cleanup.
    public int phase, heldOrdinal, errorKind, errorCode;
    public int identityMismatchMask, snapshotMismatchMask;
    public int outputStage;
    public long firstReadChangeCount, sealedOutputs;
    private bool faulted;
    private int pinPhase = 100;
    public void SetPhase(int value) { if (!faulted) phase = value; }
    private void Fault(int kind, int code)
    {
        if (!faulted) { faulted = true; errorKind = kind; errorCode = code; }
    }
    public void RecordManagedFault(int hresult) { Fault(3, hresult); }

    public SelectedAccountMaterializationPins(Action check) { before = check; }
    private void Need(bool value)
    {
        if (!value) { Fault(1, phase); throw new InvalidOperationException("Public preparation refused."); }
    }
    private void Tick()
    {
        try { before(); Need(owned.Count < 512); }
        catch (Exception error) { RecordManagedFault(error.HResult); throw; }
    }
    private FileStream Writer(SafeFileHandle handle)
    {
        SetPhase(304);
        try { return new FileStream(handle, FileAccess.ReadWrite, 65536, false); }
        catch (Exception error) { RecordManagedFault(error.HResult); throw; }
    }
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
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error(); Fault(2, error);
            handle.Dispose(); Need(false);
        }
        return handle;
    }
    private Info Information(SafeFileHandle handle)
    {
        Tick(); Need(++metadata <= 32768);
        Info info; bool found = GetFileInformationByHandle(handle, out info);
        if (!found) { int error = Marshal.GetLastWin32Error(); Fault(2, error); }
        Need(found); return info;
    }
    private SelectedAccountFileIdentity Snapshot(SafeFileHandle handle)
    {
        Info info = Information(handle); Basic basic = new Basic();
        Tick(); metadata += 2; Need(metadata <= 32768);
        uint fileType = GetFileType(handle);
        bool validShape = fileType == 1 && (info.Attributes & 0x410) == 0 && info.Links == 1;
        if (!validShape && !faulted)
            snapshotMismatchMask = (fileType != 1 ? 1 : 0) |
                ((info.Attributes & 0x410) != 0 ? 2 : 0) | (info.Links != 1 ? 4 : 0);
        Need(validShape);
        bool found = GetFileInformationByHandleEx(handle, 0, out basic, (uint)Marshal.SizeOf(typeof(Basic)));
        if (!found) { int error = Marshal.GetLastWin32Error(); Fault(2, error); }
        Need(found);
        bool sameAttributes = basic.Attributes == info.Attributes;
        if (!sameAttributes && !faulted) snapshotMismatchMask = 8;
        Need(sameAttributes);
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
        if (count == 0) { int error = Marshal.GetLastWin32Error(); Fault(2, error); }
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
        bool created = CreateDirectory(path, IntPtr.Zero);
        if (!created) { int error = Marshal.GetLastWin32Error(); Fault(2, error); }
        Need(created); HoldDirectory(path);
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
    private void NeedStableIdentity(SelectedAccountFileIdentity current, SelectedAccountFileIdentity expected)
    {
        bool same = current.Same(expected);
        if (!same && !faulted)
        {
            identityMismatchMask = (current.volume != expected.volume ? 1 : 0) |
                (current.index != expected.index ? 2 : 0) |
                (current.attributes != expected.attributes ? 4 : 0) |
                (current.links != expected.links ? 8 : 0) |
                (current.created != expected.created ? 16 : 0) |
                (current.modified != expected.modified ? 32 : 0) |
                (current.changed != expected.changed ? 64 : 0) |
                (current.length != expected.length ? 128 : 0);
        }
        Need(same);
    }
    private SafeFileHandle ObservationHandle(SelectedAccountHeldFile file)
    {
        return file.OutputObservationHandle ?? file.Stream.SafeFileHandle;
    }
    private void Stable(SelectedAccountHeldFile file, int phaseBase)
    {
        SetPhase(phaseBase); NeedStableIdentity(Snapshot(ObservationHandle(file)), file.identity);
        SetPhase(phaseBase + 1); Name(ObservationHandle(file), file.path);
        SetPhase(phaseBase + 2);
        using (SafeFileHandle named = Open(file.path, 0x80, 1, 3, 0x00200000))
        {
            try
            {
                SetPhase(phaseBase + 3); Name(named, file.path);
                SetPhase(phaseBase + 4); NeedStableIdentity(Snapshot(named), file.identity);
            }
            catch (Exception error) { RecordManagedFault(error.HResult); throw; }
        }
    }
    public SelectedAccountHeldFile Pin(string path, long length, string hash)
    {
        SetPhase(pinPhase + 1); Canonical(path); Need(length > 0 && length <= 67108864 && hash.Length == 64 &&
            hash.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
        SetPhase(pinPhase + 2); HoldDirectory(Path.GetDirectoryName(path));
        SetPhase(pinPhase + 3);
        SafeFileHandle handle = Open(path, 0x80000000, 1, 3, 0x00200000); FileStream stream = null;
        try
        {
            SetPhase(pinPhase + 4); SelectedAccountFileIdentity identity = Snapshot(handle); Need(identity.length == length);
            SetPhase(pinPhase + 5); Name(handle, path);
            SetPhase(pinPhase + 6); stream = new FileStream(handle, FileAccess.Read, 65536, false);
            SetPhase(pinPhase + 7); Need(Hash(stream, length) == hash);
            SelectedAccountHeldFile file = new SelectedAccountHeldFile { Stream = stream, path = path,
                sha256 = hash, identity = identity };
            Stable(file, pinPhase + 70); SetPhase(pinPhase + 9);
            stream.Position = 0; owned.Add(stream); files.Add(file); return file;
        }
        catch (Exception error)
        {
            RecordManagedFault(error.HResult);
            if (stream != null) stream.Dispose(); else handle.Dispose(); throw;
        }
    }
    public SelectedAccountHeldFile Copy(string source, string target, long length, string hash)
    {
        if (!faulted) outputStage = 0;
        pinPhase = 100; SetPhase(100);
        SelectedAccountHeldFile input = Pin(source, length, hash);
        SetPhase(301); Canonical(target);
        SetPhase(302); HoldDirectory(Path.GetDirectoryName(target));
        SelectedAccountFileIdentity original;
        SetPhase(303);
        using (SafeFileHandle handle = Open(target, 0xc0000000, 1, 1, 0x00200000))
        {
            try
            {
                using (FileStream writer = Writer(handle))
                {
                    try
                    {
                        SetPhase(305); original = Snapshot(handle); Need(original.length == 0);
                        SetPhase(306); Name(handle, target);
                        SetPhase(307); input.Stream.Position = 0;
                        byte[] buffer = new byte[65536]; long total = 0;
                        try
                        {
                            while (total < length)
                            {
                                SetPhase(308);
                                int count = Read(input.Stream, buffer, (int)Math.Min(buffer.Length, length - total)); Need(count > 0);
                                SetPhase(309); Tick(); Need(++writes <= 32768);
                                writtenBytes += count; Need(writtenBytes <= 134217728);
                                writer.Write(buffer, 0, count); total += count;
                            }
                            SetPhase(310); Need(Read(input.Stream, buffer, 1) == 0);
                            SetPhase(311); writer.Flush(true);
                            Stable(input, 320); SetPhase(313); Tick();
                        }
                        catch (Exception error) { RecordManagedFault(error.HResult); throw; }
                        finally { Array.Clear(buffer, 0, buffer.Length); }
                        SetPhase(315);
                    }
                    catch (Exception error) { RecordManagedFault(error.HResult); throw; }
                }
            }
            catch (Exception error) { RecordManagedFault(error.HResult); throw; }
        }
        SelectedAccountHeldFile output = EstablishOutput(target, length, hash, original);
        SetPhase(318); output.sourceIdentity = input.identity; Tick(); return output;
    }
    // Copy alone supplies a fresh CREATE_NEW public destination after closing its writer.
    // This is not an alternate input Pin or a way to refresh an existing baseline.
    private SelectedAccountHeldFile EstablishOutput(string path, long length, string hash,
        SelectedAccountFileIdentity original)
    {
        SetPhase(200); SetPhase(201); Canonical(path);
        SetPhase(202); HoldDirectory(Path.GetDirectoryName(path));
        SetPhase(203);
        SafeFileHandle handle = Open(path, 0x80000000, 1, 3, 0x00200000); FileStream stream = null;
        try
        {
            SetPhase(204); SelectedAccountFileIdentity initial = Snapshot(handle); Need(initial.length == length);
            outputStage = 1;
            SetPhase(205); Name(handle, path);
            SetPhase(206); stream = new FileStream(handle, FileAccess.Read, 65536, false);
            SetPhase(207); Need(Hash(stream, length) == hash);
            SelectedAccountHeldFile file;
            // The first named identity query is part of fresh output establishment.
            // Reuse this handle for full agreement; do not open repeatedly until quiet.
            SetPhase(272);
            using (SafeFileHandle named = Open(path, 0x80, 1, 3, 0x00200000))
            {
                SetPhase(273); Name(named, path);
                SetPhase(220); SelectedAccountFileIdentity namedInitial = Snapshot(named);
                int namedMask = (namedInitial.volume != initial.volume ? 1 : 0) |
                    (namedInitial.index != initial.index ? 2 : 0) |
                    (namedInitial.attributes != initial.attributes ? 4 : 0) |
                    (namedInitial.links != initial.links ? 8 : 0) |
                    (namedInitial.created != initial.created ? 16 : 0) |
                    (namedInitial.modified != initial.modified ? 32 : 0) |
                    (namedInitial.length != initial.length ? 128 : 0);
                if (namedMask != 0 && !faulted) identityMismatchMask = namedMask;
                Need(namedMask == 0);
                SetPhase(317); Need(namedInitial.volume == original.volume && namedInitial.index == original.index &&
                    namedInitial.created == original.created);
                SetPhase(220); SelectedAccountFileIdentity observed = Snapshot(handle);
                // All seven non-ChangeTime fields must agree across this first window.
                int mask = (observed.volume != initial.volume ? 1 : 0) |
                    (observed.index != initial.index ? 2 : 0) |
                    (observed.attributes != initial.attributes ? 4 : 0) |
                    (observed.links != initial.links ? 8 : 0) |
                    (observed.created != initial.created ? 16 : 0) |
                    (observed.modified != initial.modified ? 32 : 0) |
                    (observed.length != initial.length ? 128 : 0);
                if (mask != 0 && !faulted) identityMismatchMask = mask;
                Need(mask == 0);
                SetPhase(317); Need(observed.volume == original.volume && observed.index == original.index &&
                    observed.created == original.created);
                if (namedInitial.changed != initial.changed || observed.changed != initial.changed) firstReadChangeCount++;
                file = new SelectedAccountHeldFile { Stream = stream, OutputObservationHandle = handle, path = path,
                    sha256 = hash, identity = observed, outputInitialIdentity = initial, outputFirstReadIdentity = observed,
                    outputFirstNamedIdentity = namedInitial };
                // Full held/named agreement establishes a prospective baseline, never continuity.
                SetPhase(270); NeedStableIdentity(Snapshot(handle), file.identity);
                SetPhase(271); Name(handle, path);
                SetPhase(273); Name(named, path);
                SetPhase(274); NeedStableIdentity(Snapshot(named), file.identity);
            }
            outputStage = 2;
            SetPhase(240); Need(Hash(stream, length) == hash);
            Stable(file, 280); SetPhase(209);
            stream.Position = 0; owned.Add(stream); files.Add(file);
            outputStage = 3; sealedOutputs++; return file;
        }
        catch (Exception error)
        {
            RecordManagedFault(error.HResult);
            if (stream != null) stream.Dispose(); else handle.Dispose(); throw;
        }
    }
    public byte[] ReadControl(SelectedAccountHeldFile file, int maximum)
    {
        Need(file.identity.length <= maximum); Stable(file, 600); file.Stream.Position = 0;
        byte[] result = new byte[(int)file.identity.length], buffer = new byte[65536]; int offset = 0;
        while (offset < result.Length)
        {
            int count = Read(file.Stream, buffer, Math.Min(buffer.Length, result.Length - offset)); Need(count > 0);
            Buffer.BlockCopy(buffer, 0, result, offset, count); offset += count;
        }
        Need(Read(file.Stream, buffer, 1) == 0); Array.Clear(buffer, 0, buffer.Length); Stable(file, 610); return result;
    }
    public void CheckAll()
    {
        for (int index = 0; index < files.Count; index++)
        {
            if (!faulted) heldOrdinal = index + 1;
            Stable(files[index], 400);
        }
        SetPhase(405); Tick();
    }
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
