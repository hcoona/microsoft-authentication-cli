// Inert concrete public-only fixture admission. Runtime inputs remain unaccepted.
#nullable enable
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace ConfidentialNativeCaller;
internal sealed class AcceptedFixtureInputs : IDisposable
{
    internal const string Root=@"C:\Temp\azureauth-windows-slice-108\confidential-checks-v7";
    private readonly string admissionPath,admissionSha,batchNonce,protocolSha,recordsRoot;
    private readonly long batchEnd,terminalEnd;
    private long accessDeadline;
    private readonly FixtureNativePins pins;
    private readonly SyntheticNativeBaseline baseline=new();
    internal string NativeBaselineSha256=>baseline.Sha256;
    private readonly Dictionary<string,string> nonces=new(StringComparer.Ordinal);
    private readonly Dictionary<string,string> hashes=new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string,PublicPlan> plans=new(StringComparer.Ordinal);
    private readonly HashSet<string> readLeaves=new(StringComparer.Ordinal);
    private readonly HashSet<string> writtenLeaves=new(StringComparer.Ordinal);
    private string? role,caseId;
    private bool disposed;
    internal long RoleBoundEnd {get;private set;}
    private static readonly string[] CaseIds=["N1","N2","N3"];
    internal AcceptedFixtureInputs(string path,string sha,long originalBatchEnd,long? admissionEnd=null)
    {
        PrivateRequest.Require(OperatingSystem.IsWindows() && Stopwatch.IsHighResolution && Stopwatch.Frequency>0);
        admissionPath=path;admissionSha=sha;batchEnd=originalBatchEnd;accessDeadline=Math.Min(batchEnd,admissionEnd??batchEnd);
        terminalEnd=CallerRules.Add(batchEnd,10000,Stopwatch.Frequency);
        PrivateRequest.Require(batchEnd>Stopwatch.GetTimestamp() &&
            batchEnd<=CallerRules.Add(Stopwatch.GetTimestamp(),300000,Stopwatch.Frequency));
        PrivateRequest.Require(path==Root+@"\control\fixture-admission.json" && Hash(sha));
        CheckOrdinaryEnvironment();pins=new FixtureNativePins(Before);
        try
        {
            FixtureHeldFile admission=pins.Pin(path,sha,-1,262144);
            using JsonDocument doc=JsonDocument.Parse(pins.Read(admission,262144),new JsonDocumentOptions{MaxDepth=8});
            JsonElement data=doc.RootElement;
            Members(data,"schema","admitted","scope","identityMode","batchNonce","caseNonces","protocolSha256","pins");
            PrivateRequest.Require(Text(data,"schema")=="confidential-fixture-admission-v2" &&
                Text(data,"identityMode")==SyntheticNativeBaseline.Mode &&
                data.GetProperty("admitted").ValueKind==JsonValueKind.True && Text(data,"scope")=="synthetic-native-only");
            batchNonce=Text(data,"batchNonce");protocolSha=Text(data,"protocolSha256");
            PrivateRequest.Require(IsNonce(batchNonce) && Hash(protocolSha));
            JsonElement cases=data.GetProperty("caseNonces");Members(cases,CaseIds);
            foreach(string id in CaseIds){string nonce=Text(cases,id);PrivateRequest.Require(IsNonce(nonce));nonces.Add(id,nonce);}
            PrivateRequest.Require(nonces.Values.Append(batchNonce).Distinct(StringComparer.Ordinal).Count()==4);
            Dictionary<string,FixtureCatalogEntry> expected=FixtureInputCatalog.Required();
            JsonElement entries=data.GetProperty("pins");PrivateRequest.Require(entries.ValueKind==JsonValueKind.Array && entries.GetArrayLength()==202);
            long total=0;
            foreach(JsonElement item in entries.EnumerateArray())
            {
                Before();Members(item,"relative","bytes","sha256","linuxIdentity");
                string relative=Text(item,"relative"),hash=Text(item,"sha256");long bytes=item.GetProperty("bytes").GetInt64();
                PrivateRequest.Require(expected.Remove(relative,out FixtureCatalogEntry? exact) && Hash(hash) && !hashes.ContainsKey(relative));
                PrivateRequest.Require(bytes>0 && bytes<=exact!.MaximumBytes && (exact.Bytes<0 || bytes==exact.Bytes) &&
                    (exact.Sha256 is null || hash==exact.Sha256));
                total=checked(total+bytes);PrivateRequest.Require(total<=100663296);
                SyntheticNativeBaseline.RequireLinuxIdentity(item.GetProperty("linuxIdentity"),bytes);
                FixtureHeldFile held=pins.Pin(Root+"\\"+relative,hash,bytes,exact.MaximumBytes);
                baseline.Add(relative,hash,held);hashes.Add(relative,hash);
            }
            PrivateRequest.Require(expected.Count==0);
            baseline.Seal(Root,batchNonce,admissionSha,protocolSha,202,Before);
            recordsRoot=Root+@"\records\"+batchNonce;
            foreach(string id in CaseIds)plans.Add(id,new PublicPlan { SelfImage=Root+@"\artifact\NativeCaller.exe",
                ProductImage=Root+@"\artifact\SyntheticSubject.exe",WorkingDirectory=Root,ReceiptDirectory=recordsRoot+"\\"+id,
                ProductSha256=hashes[@"artifact\SyntheticSubject.exe"],CallerSha256=hashes[@"artifact\NativeCaller.exe"],ProtocolSha256=protocolSha });
            Before();
        }
        catch{pins.Dispose();throw;}
    }
    private void Before(){PrivateRequest.Require(!disposed);CallerRules.Before(Stopwatch.GetTimestamp(),accessDeadline);}
    internal PublicPlan Plan(string id){Before();PrivateRequest.Require(plans.ContainsKey(id));return plans[id];}
    internal string Nonce(string id){Before();PrivateRequest.Require(nonces.ContainsKey(id));return nonces[id];}
    private static bool IsNonce(string value)=>Regex.IsMatch(value,"\\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\\z");
    private static bool Hash(string value)=>Regex.IsMatch(value,"\\A[0-9a-f]{64}\\z");
    private static string Id(Group group)=>group switch {Group.R5Pair=>"N1",Group.R7=>"N2",Group.R1=>"N3",_=>throw new SafeFailure(Fault.Admission)};
    private void Image(string expected)=>PrivateRequest.Require(string.Equals(Environment.ProcessPath,Root+@"\artifact\"+expected,StringComparison.OrdinalIgnoreCase));
    internal IDisposable HoldBatch()
    {
        Before();PrivateRequest.Require(role is null);Image("FixtureDriver.exe");role="batch";
        pins.CreateDirectoryExclusive(recordsRoot);
        foreach(string id in CaseIds)pins.CreateDirectoryExclusive(recordsRoot+"\\"+id);
        PrivateRequest.Require(writtenLeaves.Add("native-baseline.json"));
        pins.CreatePinnedMap(recordsRoot+"\\native-baseline.json",baseline.Bytes,Before);
        return this;
    }
    internal IDisposable HoldRoleBound(PublicPlan plan,Group group,string nonce,bool worker,long boundEnd)
    {
        Before();PrivateRequest.Require(role is null);Image("NativeCaller.exe");string id=Id(group);
        PrivateRequest.Require(ReferenceEquals(plan,plans[id]) && nonce==nonces[id] && boundEnd>Stopwatch.GetTimestamp() && boundEnd<=batchEnd);
        role=worker?"worker":"supervisor";caseId=id;RoleBoundEnd=boundEnd;
        pins.HoldDirectory(recordsRoot);pins.HoldDirectory(plan.ReceiptDirectory);
        string path=plan.ReceiptDirectory+"\\"+role+"-identity.json";
        FixtureHeldFile file=pins.Pin(path,null,-1,4096);
        using JsonDocument doc=JsonDocument.Parse(pins.Read(file,4096),new JsonDocumentOptions{MaxDepth=3});
        JsonElement data=doc.RootElement;Members(data,"schema","case","role","nonce","admissionSha256","nativeBaselineSha256","pid","createdFileTime","batchWorkEnd","boundEnd","noExperimentLive");
        PrivateRequest.Require(Text(data,"schema")=="synthetic-created-role-v1" && Text(data,"case")==id && Text(data,"role")==role &&
            Text(data,"nonce")==nonce && Text(data,"admissionSha256")==admissionSha && Text(data,"nativeBaselineSha256")==baseline.Sha256 &&
            data.GetProperty("batchWorkEnd").GetInt64()==batchEnd &&
            data.GetProperty("boundEnd").GetInt64()==boundEnd && data.GetProperty("noExperimentLive").ValueKind==JsonValueKind.False);
        FixtureNativePins.CurrentIdentity(data.GetProperty("pid").GetUInt32(),data.GetProperty("createdFileTime").GetInt64());
        if(worker)FixtureNativePins.RequireCurrentJob("Local\\azureauth-confidential-108-"+group+"-"+nonce);
        Before();return this;
    }
    internal string[] RoleArguments(Group group,string nextRole,long boundEnd)
    {
        Before();PrivateRequest.Require(nextRole is "supervisor" or "worker" && boundEnd>Stopwatch.GetTimestamp() && boundEnd<=batchEnd);
        string id=Id(group);PrivateRequest.Require(nextRole=="supervisor"?role=="batch":role=="supervisor" && caseId==id);
        return ["--fixture-"+nextRole,group.ToString(),nonces[id],admissionPath,admissionSha,
            batchEnd.ToString(CultureInfo.InvariantCulture),boundEnd.ToString(CultureInfo.InvariantCulture)];
    }
    internal IDisposable BindCreated(Group group,string nextRole,Child child,long boundEnd)
    {
        _=RoleArguments(group,nextRole,boundEnd);string id=Id(group);
        PrivateRequest.Require(!child.Exited() && child.ProcessId>0 && child.CreatedFileTime>0);
        string leaf=id+"/"+nextRole+"-identity.json";PrivateRequest.Require(writtenLeaves.Add(leaf));
        byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(new { schema="synthetic-created-role-v1",@case=id,role=nextRole,
            nonce=nonces[id],admissionSha256=admissionSha,nativeBaselineSha256=baseline.Sha256,
            pid=child.ProcessId,createdFileTime=child.CreatedFileTime,batchWorkEnd=batchEnd,boundEnd,noExperimentLive=false });
        // The caller has the original suspended creation handle. No PID lookup is used.
        return pins.CreatePinnedRecord(plans[id].ReceiptDirectory+"\\"+nextRole+"-identity.json",bytes,Before);
    }
    internal byte[] ReadHeldReceipt(string id,string leaf,int maximumBytes)
    {
        Before();PrivateRequest.Require(role=="batch" && maximumBytes==4096 && CaseIds.Contains(id,StringComparer.Ordinal));
        string[] slots=id=="N1"?["R5a","R5b"]:id=="N2"?["R7"]:["R1"];
        PrivateRequest.Require(slots.Any(s=>leaf==s+"-reservation.json" || leaf==s+"-terminal.json") && readLeaves.Add(id+"/"+leaf));
        FixtureHeldFile file=pins.Pin(plans[id].ReceiptDirectory+"\\"+leaf,null,-1,maximumBytes);return pins.Read(file,maximumBytes);
    }
    internal void PublishExclusive(string leaf,byte[] safeBytes)
    {
        PrivateRequest.Require(role=="batch" && safeBytes.Length is >0 and <=4096 &&
            (leaf=="batch.json" || CaseIds.Any(id=>leaf==id+"-case.json")) && writtenLeaves.Add(leaf));
        // This is the original batch terminal allowance; no new timestamp starts it.
        if(leaf=="batch.json")accessDeadline=terminalEnd;
        Before();pins.CreatePinnedRecord(recordsRoot+"\\"+leaf,safeBytes,Before);Before();
    }
    private static void CheckOrdinaryEnvironment()
    {
        // The environment is never rewritten. Reject optional runtime injection or
        // alternate probing controls rather than silently constructing another profile.
        foreach(DictionaryEntry item in Environment.GetEnvironmentVariables())
        {
            string key=(string)item.Key;
            bool runtime=key.StartsWith("DOTNET_",StringComparison.OrdinalIgnoreCase) || key.StartsWith("COMPlus_",StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("CORECLR_",StringComparison.OrdinalIgnoreCase) || key.StartsWith("COR_",StringComparison.OrdinalIgnoreCase);
            if(runtime)PrivateRequest.Require(string.Equals(key,"DOTNET_CLI_TELEMETRY_OPTOUT",StringComparison.OrdinalIgnoreCase));
        }
    }
    private static void Members(JsonElement value,params string[] expected)
    {
        PrivateRequest.Require(value.ValueKind==JsonValueKind.Object);var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(JsonProperty field in value.EnumerateObject())PrivateRequest.Require(seen.Add(field.Name) && expected.Contains(field.Name,StringComparer.Ordinal));
        PrivateRequest.Require(seen.Count==expected.Length);
    }
    private static string Text(JsonElement root,string name)
    {JsonElement value=root.GetProperty(name);PrivateRequest.Require(value.ValueKind==JsonValueKind.String);return value.GetString()!;}
    public void Dispose(){if(disposed)return;disposed=true;pins.Dispose();}
}
