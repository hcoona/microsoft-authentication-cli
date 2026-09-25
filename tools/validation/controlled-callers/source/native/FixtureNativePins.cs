// Source-only native pinning. Derived from accepted launcher directory holds and
// WindowsWslObserver regular-file checks; stricter stable identity checks are local.
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
namespace ConfidentialNativeCaller;
internal readonly record struct FixtureFileIdentity(uint Volume,ulong Index,uint Attributes,long Created,long Modified,
    long Changed,long Length,uint Links);
internal sealed class FixtureHeldFile(FileStream stream,FixtureFileIdentity identity) : IDisposable
{
    internal readonly FileStream Stream=stream;
    internal readonly FixtureFileIdentity Identity=identity;
    public void Dispose()=>Stream.Dispose();
}
internal sealed class FixtureNativePins : IDisposable
{
    private readonly Dictionary<string,SafeFileHandle> directories=new(StringComparer.OrdinalIgnoreCase);
    private readonly List<IDisposable> held=[];
    private readonly Action before;
    internal FixtureNativePins(Action beforeRead){before=beforeRead;}
    internal static void Need(bool value){if(!value)throw new SafeFailure(Fault.Admission);}
    internal static void Canonical(string path)
    {
        Need(path.Length is >=3 and <=1024 && path.StartsWith(@"C:\",StringComparison.Ordinal) &&
            !path.Contains('/') && !path[2..].Contains(':') && !path.Any(char.IsControl) && Path.GetFullPath(path)==path);
        foreach(string part in path[3..].Split('\\'))
            Need(part.Length>0 && part!="." && part!=".." && !part.EndsWith('.') && !part.EndsWith(' '));
    }
    internal void HoldDirectory(string path)
    {
        before();if(directories.ContainsKey(path))return;
        if(path!=@"C:\")Canonical(path);
        string? parent=path==@"C:\"?null:Path.GetDirectoryName(path);
        if(parent is not null)HoldDirectory(parent);
        SafeFileHandle handle=Open(path,0x80,3,3,0x02200000);
        try
        {
            Info info=Information(handle);Need(GetFileType(handle)==1 && (info.Attributes&0x410)==0x10);
            RequireName(handle,path);before();directories.Add(path,handle);held.Add(handle);
        }
        catch{handle.Dispose();throw;}
    }
    internal void CreateDirectoryExclusive(string path)
    {
        Canonical(path);HoldDirectory(Path.GetDirectoryName(path)!);before();
        Need(CreateDirectory(path,IntPtr.Zero));HoldDirectory(path);
    }
    internal FixtureHeldFile Pin(string path,string? hash,long length,long maximum,FixtureFileIdentity? expected=null)
    {
        Canonical(path);Need(maximum is >0 and <=67108864 && length>=-1 && length<=maximum);
        HoldDirectory(Path.GetDirectoryName(path)!);before();
        SafeFileHandle handle=Open(path,0x80000000,1,3,0x00200000);
        FileStream? stream=null;
        try
        {
            FixtureFileIdentity identity=Snapshot(handle);
            Need(identity.Links==1 && identity.Length>=0 && identity.Length<=maximum && (length<0 || identity.Length==length));
            if(expected is FixtureFileIdentity pin)Need(identity==pin);
            RequireName(handle,path);stream=new FileStream(handle,FileAccess.Read,65536,false);
            if(hash is not null)
            {
                Need(hash.Length==64 && hash.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f'));
                using var digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] buffer=new byte[65536];long consumed=0;
                try
                {
                    while(consumed<identity.Length)
                    {
                        before();int count=stream.Read(buffer,0,(int)Math.Min(buffer.Length,identity.Length-consumed));
                        Need(count>0);digest.AppendData(buffer,0,count);consumed+=count;
                    }
                    before();Need(stream.ReadByte()==-1);
                    Need(Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant()==hash);
                }
                finally{Array.Clear(buffer);}
            }
            before();Need(Snapshot(handle)==identity);
            using(SafeFileHandle named=Open(path,0x80,1,3,0x00200000))Need(Snapshot(named)==identity);
            stream.Position=0;var retained=new FixtureHeldFile(stream,identity);held.Add(retained);return retained;
        }
        catch{if(stream is not null)stream.Dispose();else handle.Dispose();throw;}
    }
    internal byte[] Read(FixtureHeldFile file,int maximum)
    {
        before();Need(file.Identity.Length<=maximum && Snapshot(file.Stream.SafeFileHandle)==file.Identity);
        file.Stream.Position=0;byte[] result=new byte[checked((int)file.Identity.Length)];int used=0;
        while(used<result.Length){before();int got=file.Stream.Read(result,used,result.Length-used);Need(got>0);used+=got;}
        before();Need(file.Stream.ReadByte()==-1 && Snapshot(file.Stream.SafeFileHandle)==file.Identity);return result;
    }
    internal FixtureHeldFile CreatePinnedRecord(string path,byte[] bytes,Action checkTime)
        => CreatePinnedOutput(path,bytes,4096,checkTime);
    internal FixtureHeldFile CreatePinnedMap(string path,byte[] bytes,Action checkTime)
    {
        Need(Path.GetFileName(path)=="native-baseline.json");
        return CreatePinnedOutput(path,bytes,262144,checkTime);
    }
    private FixtureHeldFile CreatePinnedOutput(string path,byte[] bytes,int maximum,Action checkTime)
    {
        Need(bytes.Length>0 && bytes.Length<=maximum);Canonical(path);HoldDirectory(Path.GetDirectoryName(path)!);checkTime();
        FixtureFileIdentity original;
        using(SafeFileHandle handle=Open(path,0xc0000000,1,1,0x00200000))
        using(var stream=new FileStream(handle,FileAccess.ReadWrite,4096,false))
        {
            original=Snapshot(handle);Need(original.Length==0 && original.Links==1);RequireName(handle,path);
            stream.Write(bytes);stream.Flush(true);checkTime();
        }
        // The gap after our own writer closes is checked by original native identity
        // plus exact bytes. The retained read handle then denies write/delete sharing.
        string hash=Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        FixtureHeldFile pinned=Pin(path,hash,bytes.Length,maximum);
        Need(pinned.Identity.Volume==original.Volume && pinned.Identity.Index==original.Index &&
            pinned.Identity.Created==original.Created);checkTime();return pinned;
    }
    internal static FixtureFileIdentity Snapshot(SafeFileHandle file)
    {
        Info i=Information(file);Need(GetFileType(file)==1 && (i.Attributes&0x410)==0 && i.Links==1);
        Need(GetFileInformationByHandleEx(file,0,out Basic basic,(uint)Marshal.SizeOf<Basic>()) && basic.Attributes==i.Attributes);
        return new(i.Volume,((ulong)i.IndexHigh<<32)|i.IndexLow,basic.Attributes,basic.Created,basic.Modified,
            basic.Changed,checked((long)(((ulong)i.SizeHigh<<32)|i.SizeLow)),i.Links);
    }
    private static Info Information(SafeFileHandle file)
    {Need(GetFileInformationByHandle(file,out Info info));return info;}
    private static SafeFileHandle Open(string path,uint access,uint share,uint creation,uint flags)
    {
        SafeFileHandle result=CreateFile(path,access,share,IntPtr.Zero,creation,flags,IntPtr.Zero);
        if(result.IsInvalid){result.Dispose();throw new SafeFailure(Fault.Admission);}return result;
    }
    private static void RequireName(SafeFileHandle handle,string path)
    {
        var name=new StringBuilder(2048);uint count=GetFinalPathNameByHandle(handle,name,(uint)name.Capacity,0);
        Need(count>0 && count<name.Capacity && string.Equals(name.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase));
    }
    internal static void CurrentIdentity(uint pid,long created)
    {
        Need(GetCurrentProcessId()==pid && GetProcessTimes(GetCurrentProcess(),out long actual,out _,out _,out _) && actual==created);
    }
    internal static void RequireCurrentJob(string name)
    {
        using SafeFileHandle job=OpenJobObject(4,false,name);Need(!job.IsInvalid && IsProcessInJob(GetCurrentProcess(),job,out bool member) && member);
    }
    public void Dispose()
    {
        for(int i=held.Count-1;i>=0;i--)held[i].Dispose();held.Clear();directories.Clear();
    }
    [StructLayout(LayoutKind.Sequential)]private struct Info
    {internal uint Attributes,CreatedLow,CreatedHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    [StructLayout(LayoutKind.Sequential)]private struct Basic
    {internal long Created,Accessed,Modified,Changed;internal uint Attributes;}
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",EntryPoint="CreateDirectoryW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool CreateDirectory(string path,IntPtr security);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int kind,out Basic info,uint size);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern uint GetFileType(SafeFileHandle handle);
    [DllImport("kernel32.dll",EntryPoint="GetFinalPathNameByHandleW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder name,uint length,uint flags);
    [DllImport("kernel32.dll")]private static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll")]private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetProcessTimes(IntPtr handle,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",EntryPoint="OpenJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle OpenJobObject(uint access,bool inherit,string name);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool IsProcessInJob(IntPtr process,SafeFileHandle job,out bool member);
}

// Synthetic admission only. This records successful first-held snapshots; it does
// not assert a native identity before the open or metadata immutability from sharing.
internal sealed class SyntheticNativeBaseline
{
    internal const string Mode="synthetic-first-held-v1";
    private readonly SortedDictionary<string,(string Hash,FixtureHeldFile File)> rows=new(StringComparer.Ordinal);
    internal byte[] Bytes {get;private set;}=[];
    internal string Sha256 {get;private set;}="";
    internal void Add(string relative,string hash,FixtureHeldFile file)
    {
        FixtureNativePins.Need(Bytes.Length==0 && rows.Count<202 && relative.Length<=256);
        FixtureFileIdentity id=file.Identity;
        FixtureNativePins.Need(id.Index>0 && id.Created>0 && id.Modified>0 && id.Changed>0 && id.Links==1);
        rows.Add(relative,(hash,file));
    }
    internal void Seal(string root,string original,string admissionSha,string protocolSha,int count,Action before)
    {
        before();FixtureNativePins.Need(Bytes.Length==0 && count is 200 or 202 && rows.Count==count);
        using var memory=new MemoryStream();
        using(var json=new Utf8JsonWriter(memory))
        {
            json.WriteStartObject();json.WriteString("schema","synthetic-native-baseline-v1");
            json.WriteString("identityMode",Mode);json.WriteString("root",root);json.WriteString("original",original);
            json.WriteString("admissionSha256",admissionSha);json.WriteString("protocolSha256",protocolSha);
            json.WriteStartArray("rows");
            foreach(var row in rows)
            {
                before();FixtureFileIdentity id=row.Value.File.Identity;
                json.WriteStartObject();json.WriteString("relative",row.Key);json.WriteNumber("bytes",id.Length);
                json.WriteString("sha256",row.Value.Hash);json.WriteStartObject("identity");
                json.WriteNumber("volume",id.Volume);json.WriteNumber("index",id.Index);json.WriteNumber("attributes",id.Attributes);
                json.WriteNumber("created",id.Created);json.WriteNumber("modified",id.Modified);json.WriteNumber("changed",id.Changed);
                json.WriteNumber("links",id.Links);json.WriteEndObject();json.WriteEndObject();
                json.Flush();FixtureNativePins.Need(memory.Length<=262144);
            }
            json.WriteEndArray();json.WriteEndObject();json.Flush();
        }
        FixtureNativePins.Need(memory.Length is >0 and <=262144);Bytes=memory.ToArray();
        Sha256=Convert.ToHexString(SHA256.HashData(Bytes)).ToLowerInvariant();before();
    }
    internal static void RequireLinuxIdentity(JsonElement value,long bytes)
    {
        // Admission provenance is interpreted by the Linux controller, never converted
        // into native volume/index/times. Enforce a distinct exact row shape here.
        FixtureNativePins.Need(value.ValueKind==JsonValueKind.Array && value.GetArrayLength()==9);
        foreach(JsonElement field in value.EnumerateArray())
            FixtureNativePins.Need(field.ValueKind==JsonValueKind.Number && (field.TryGetInt64(out _) || field.TryGetUInt64(out _)));
        FixtureNativePins.Need((value[2].GetInt64()&61440)==32768 && value[5].GetInt64()==bytes && value[8].GetInt64()==1);
    }
}
