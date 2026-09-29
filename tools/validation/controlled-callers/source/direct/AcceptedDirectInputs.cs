// Inert concrete direct admission. External authority and final artifact pins remain closed.
#nullable enable
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DirectNativePins=ConfidentialNativeCaller.FixtureNativePins;
using DirectFileIdentity=ConfidentialNativeCaller.FixtureFileIdentity;
using DirectHeldFile=ConfidentialNativeCaller.FixtureHeldFile;
using SyntheticBaseline=ConfidentialNativeCaller.SyntheticNativeBaseline;
namespace ConfidentialWsl;
internal sealed class AcceptedDirectInputs : IDisposable
{
    internal const string Root=@"C:\Temp\azureauth-windows-slice-108\confidential-direct-v6";
    private readonly DirectNativePins pins;
    private readonly Slot slot;
    private readonly string nonce,scope;
    private readonly bool worker,soleLaunch,targetedStop;
    private readonly long workEnd;
    private DirectHeldFile? privateFile;
    private readonly SyntheticBaseline? baseline;
    private readonly string[]? baselineParts;
    private bool held,privateRead,disposed;
    internal PublicPlan Plan {get;}
    internal string AdmissionPath {get;}
    internal string AdmissionSha {get;}
    internal AcceptedDirectInputs(string path,string sha,Slot selected,string selectedNonce,bool workerRole,long deadline,string? parentBaseline)
    {
        slot=selected;nonce=selectedNonce;worker=workerRole;workEnd=deadline;AdmissionPath=path;AdmissionSha=sha;
        Need(path==Root+@"\control\"+slot+"-"+nonce+".json" && Hash(sha));
        Need(OperatingSystem.IsWindows() && Stopwatch.IsHighResolution && IntPtr.Size==8 &&
            deadline>ObserverProgram.Now && deadline<=ObserverProgram.Add(ObserverProgram.Now,145000));
        OrdinaryEnvironment();pins=new DirectNativePins(Before);
        try
        {
            DirectHeldFile admission=pins.Pin(path,sha,-1,262144);
            using JsonDocument doc=JsonDocument.Parse(pins.Read(admission,262144),new JsonDocumentOptions {MaxDepth=8});
            JsonElement data=doc.RootElement;
            bool fixture=slot==Slot.D0 || DirectRoles.Fixture(slot);
            string[] fields=["schema","scope","slot","nonce","protocolSha256","callerSha256","expectedExit","productTimeoutSeconds",
                "soleLaunchIdentityPremiseAccepted","targetedStopPremiseAccepted","accountEffectsAdmitted","calibrationAccepted",
                "pins","privateReference"];
            Members(data,fixture?fields.Append("identityMode").ToArray():fields);
            Need(Text(data,"schema")== (fixture?"confidential-direct-admission-v2":"confidential-direct-admission-v1") && Text(data,"slot")==slot.ToString() &&
                Text(data,"nonce")==nonce);
            if(fixture){Need(Text(data,"identityMode")==SyntheticBaseline.Mode);baseline=new SyntheticBaseline();}
            scope=Text(data,"scope");
            Need(scope==(fixture?"synthetic-direct":"real-direct"));
            Need(Flag(data,"accountEffectsAdmitted")==!fixture);
            bool calibrationAccepted=Flag(data,"calibrationAccepted");
            Need(slot==Slot.D0 || calibrationAccepted);
            soleLaunch=Flag(data,"soleLaunchIdentityPremiseAccepted");
            targetedStop=Flag(data,"targetedStopPremiseAccepted");
            Need(soleLaunch && (!fixture || !targetedStop));
            string protocol=Text(data,"protocolSha256"),caller=Text(data,"callerSha256");
            Need(Hash(protocol) && Hash(caller));
            int expectedExit=Number(data.GetProperty("expectedExit")),timeout=Number(data.GetProperty("productTimeoutSeconds"));
            Need(expectedExit is 0 or 1 && timeout is >=1 and <=120);
            if(fixture)Need(expectedExit==(slot==Slot.D2?1:0) && timeout==5);
            Dictionary<string,DirectCatalogEntry> expected=DirectInputCatalog.Required(slot);
            JsonElement entries=data.GetProperty("pins");Need(entries.ValueKind==JsonValueKind.Array && entries.GetArrayLength()==expected.Count);
            var hashes=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);long total=0;
            foreach(JsonElement item in entries.EnumerateArray())
            {
                DirectFailure.InputOrdinal++;
                Before();Members(item,"relative","bytes","sha256",fixture?"linuxIdentity":"identity");
                string relative=Text(item,"relative"),hash=Text(item,"sha256");long bytes=item.GetProperty("bytes").GetInt64();
                Need(expected.Remove(relative,out DirectCatalogEntry? exact) && Hash(hash) && !hashes.ContainsKey(relative));
                Need(bytes>0 && bytes<=exact!.MaximumBytes && (exact.Bytes<0 || bytes==exact.Bytes) &&
                    (exact.Sha256 is null || exact.Sha256==hash));
                total=checked(total+bytes);Need(total<=100663296);
                if(fixture)
                {
                    SyntheticBaseline.RequireLinuxIdentity(item.GetProperty("linuxIdentity"),bytes);
                    baseline!.Add(relative,hash,pins.Pin(Root+"\\"+relative,hash,bytes,exact.MaximumBytes));
                }
                else pins.Pin(Root+"\\"+relative,hash,bytes,exact.MaximumBytes,FileIdentity(item.GetProperty("identity"),bytes));
                hashes.Add(relative,hash);
            }
            DirectFailure.InputOrdinal=0;
            Need(expected.Count==0 && hashes[@"source\direct_wsl_caller.py"]==caller);
            if(fixture)
            {
                baseline!.Seal(Root,slot+"-"+nonce,AdmissionSha,protocol,200,Before);
                baselineParts=BaselineParts(baseline.Bytes,Before);
                if(worker)CompareBaseline(parentBaseline,baselineParts);
                else Need(parentBaseline is null);
            }
            else Need(parentBaseline is null);
            string product=fixture?@"artifact\SyntheticSubject.exe":@"product\Authentication.Cli.exe";
            Plan=new PublicPlan { ObserverImage=Root+@"\artifact\DirectObserver.exe",ProductImage=Root+"\\"+product,
                WorkingDirectory=Root,RecordDirectory=Root+@"\records\"+slot+"-"+nonce,ProductSha256=hashes[product],
                CallerSha256=caller,ProtocolSha256=protocol,ExpectedExit=expectedExit,ProductTimeoutSeconds=timeout,
                NativeBaselineSha256=baseline?.Sha256 };
            AdmissionCatalog.Validate(Plan);
            pins.HoldDirectory(Plan.RecordDirectory);
            JsonElement reference=data.GetProperty("privateReference");
            if(fixture)Need(reference.ValueKind==JsonValueKind.Null);
            else
            {
                Members(reference,"relative","bytes","identity");
                string relative=Text(reference,"relative");long bytes=reference.GetProperty("bytes").GetInt64();
                Need(relative==@"private\"+slot+"-"+nonce+".json" && bytes is >0 and <=262144);
                // No private content hash is computed or published. The selected accepted
                // reference is held against native write/delete replacement through use.
                privateFile=pins.Pin(Root+"\\"+relative,null,bytes,262144,FileIdentity(reference.GetProperty("identity"),bytes));
            }
            Before();
        }
        catch(Exception caught)
        {
            DirectFailure.Capture(caught is SafeFailure safe?safe.Fault:Fault.Native);
            pins.Dispose();throw;
        }
    }
    private static void Need(bool value,[CallerLineNumber] int line=0)
    { if(!value){DirectFailure.Remember(1,line);throw new SafeFailure(Fault.Admission);} }
    // Only already captured synthetic bytes enter these diagnostic fingerprints.
    // Full baseline equality remains required after every field comparison.
    private static readonly string[] BaselineFields=["volume","index","attributes","created","modified","links","changed"];
    private static string[] BaselineParts(byte[] raw,Action before)
    {
        before();Need(raw.Length is >0 and <=262144);
        using JsonDocument document=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=4});
        JsonElement root=document.RootElement,rows=root.GetProperty("rows");
        Need(rows.ValueKind==JsonValueKind.Array && rows.GetArrayLength() is >0 and <=200);
        string[] parts=new string[9];parts[0]=Digest(raw);
        for(int part=1;part<parts.Length;part++)
        {
            before();using var memory=new MemoryStream();
            using(var json=new Utf8JsonWriter(memory))
            {
                json.WriteStartArray();
                if(part==1)
                    foreach(string name in new[]{"schema","identityMode","root","original","admissionSha256","protocolSha256"})
                        root.GetProperty(name).WriteTo(json);
                foreach(JsonElement row in rows.EnumerateArray())
                {
                    before();json.WriteStartArray();row.GetProperty("relative").WriteTo(json);
                    if(part==1)
                    { row.GetProperty("bytes").WriteTo(json);row.GetProperty("sha256").WriteTo(json); }
                    else row.GetProperty("identity").GetProperty(BaselineFields[part-2]).WriteTo(json);
                    json.WriteEndArray();json.Flush();Need(memory.Length<=262144);
                }
                json.WriteEndArray();json.Flush();Need(memory.Length<=262144);
            }
            parts[part]=Digest(memory.ToArray());
        }
        before();return parts;
    }
    private static string Digest(byte[] value)=>Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    private static void CompareBaseline(string? parent,string[] local)
    {
        Need(parent is not null && parent.Length==584);
        string[] expected=parent!.Split(':');Need(expected.Length==9 && expected.All(Hash));
        Need(expected[1]==local[1]); // Header, ordered paths, lengths and content hashes.
        Need(expected[2]==local[2]); // Volume.
        Need(expected[3]==local[3]); // File index.
        Need(expected[4]==local[4]); // Attributes.
        Need(expected[5]==local[5]); // Creation time.
        Need(expected[6]==local[6]); // Modification time.
        Need(expected[7]==local[7]); // Link count.
        Need(expected[8]==local[8]); // ChangeTime, after every other field matched.
        Need(expected[0]==local[0]); // Original complete-baseline digest still required.
    }
    internal static void CheckBaselineParts(long deadline)
    {
        void CheckTime()=>ObserverProgram.Before(deadline);
        const string sample="""
            {"schema":"synthetic-native-baseline-v1","identityMode":"synthetic-first-held-v1","root":"synthetic","original":"D0","admissionSha256":"a","protocolSha256":"b","rows":[{"relative":"one","bytes":11,"sha256":"c","identity":{"volume":1,"index":2,"attributes":3,"created":4,"modified":5,"links":1,"changed":6}}]}
            """;
        string[] original=BaselineParts(Encoding.UTF8.GetBytes(sample),CheckTime);
        Need(original.SequenceEqual(BaselineParts(Encoding.UTF8.GetBytes(sample),CheckTime)));
        (string Field,string Old,string New,int Part)[] changes=[("bytes","11","12",1),
            ("volume","1","2",2),("index","2","3",3),("attributes","3","4",4),
            ("created","4","5",5),("modified","5","6",6),("links","1","2",7),("changed","6","7",8)];
        foreach(var change in changes)
        {
            string changed=sample.Replace("\""+change.Field+"\":"+change.Old,"\""+change.Field+"\":"+change.New);
            string[] actual=BaselineParts(Encoding.UTF8.GetBytes(changed),CheckTime);
            for(int part=0;part<9;part++)Need((original[part]!=actual[part])==(part==0 || part==change.Part));
        }
        Need(string.Join(":",original).Length==584);CheckTime();
    }
    private void Before(){Need(!disposed);ObserverProgram.Before(workEnd);}
    internal IDisposable Hold(PublicPlan plan,Slot selected,string selectedNonce,bool workerRole)
    {
        Before();Need(!held && ReferenceEquals(plan,Plan) && selected==slot && selectedNonce==nonce && workerRole==worker);
        Need(string.Equals(Environment.ProcessPath,Plan.ObserverImage,StringComparison.OrdinalIgnoreCase));
        // The Linux controller checks the exact Windows deployment and execute permission
        // before supervisor startup. This native supervisor holds the closure before
        // worker startup/readiness; it does not retroactively validate its own loader.
        // Worker binding follows the exact supervisor-created command and creation-time
        // Job assignment under ordinary workstation trust. No worker Job handle is opened.
        held=true;
        if(!worker && baseline is not null)pins.CreatePinnedMap(Plan.RecordDirectory+"\\native-baseline.json",baseline.Bytes,Before);
        return this;
    }
    internal PrivateExpectation Request(Slot selected)
    {
        Before();Need(held && worker && selected==slot && slot!=Slot.D0 && !privateRead);privateRead=true;
        if(DirectRoles.Fixture(slot))return DirectFixture.Expectation(slot,soleLaunch);
        Need(privateFile is not null && scope=="real-direct");
        byte[] raw=pins.Read(privateFile!,262144);
        try{return DirectRequest.FromDocument(raw,Plan,slot,nonce,soleLaunch,targetedStop);}
        finally{Array.Clear(raw);} // No erasure claim for parser strings or OS copies.
    }
    internal void Calibration(PublicPlan plan,string selectedNonce)
    { Before();Need(held && worker && slot==Slot.D0 && scope=="synthetic-direct" && privateFile is null &&
        ReferenceEquals(plan,Plan) && selectedNonce==nonce); }
    internal string[] WorkerArguments(Slot selected,string selectedNonce,long deadline)
    {
        Before();Need(held && !worker && selected==slot && selectedNonce==nonce && deadline==workEnd);
        string[] arguments=["--worker",slot.ToString(),nonce,AdmissionPath,AdmissionSha,deadline.ToString(CultureInfo.InvariantCulture)];
        return baseline is null?arguments:arguments.Append(string.Join(":",baselineParts!)).ToArray();
    }
    private static DirectFileIdentity FileIdentity(JsonElement value,long bytes)
    {
        Members(value,"volume","index","attributes","created","modified","changed","links");
        var result=new DirectFileIdentity(value.GetProperty("volume").GetUInt32(),value.GetProperty("index").GetUInt64(),
            value.GetProperty("attributes").GetUInt32(),value.GetProperty("created").GetInt64(),
            value.GetProperty("modified").GetInt64(),value.GetProperty("changed").GetInt64(),bytes,value.GetProperty("links").GetUInt32());
        Need(result.Index>0 && result.Created>0 && result.Modified>0 && result.Changed>0 && result.Links==1);return result;
    }
    private static bool Hash(string value)=>Regex.IsMatch(value,"\\A[0-9a-f]{64}\\z");
    private static string Text(JsonElement data,string name)
    {JsonElement value=data.GetProperty(name);Need(value.ValueKind==JsonValueKind.String);return value.GetString()!;}
    private static int Number(JsonElement value)
    {Need(value.ValueKind==JsonValueKind.Number);Need(value.TryGetInt32(out int result));return result;}
    private static bool Flag(JsonElement data,string name)
    {JsonElement value=data.GetProperty(name);Need(value.ValueKind is JsonValueKind.True or JsonValueKind.False);return value.GetBoolean();}
    private static void Members(JsonElement value,params string[] expected)
    {
        Need(value.ValueKind==JsonValueKind.Object);var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(JsonProperty field in value.EnumerateObject())Need(seen.Add(field.Name) && expected.Contains(field.Name,StringComparer.Ordinal));
        Need(seen.Count==expected.Length);
    }
    private static void OrdinaryEnvironment()
    {
        foreach(DictionaryEntry item in Environment.GetEnvironmentVariables())
        {
            string key=(string)item.Key;
            if(key.StartsWith("DOTNET_",StringComparison.OrdinalIgnoreCase) || key.StartsWith("COMPlus_",StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("CORECLR_",StringComparison.OrdinalIgnoreCase) || key.StartsWith("COR_",StringComparison.OrdinalIgnoreCase))
                Need(string.Equals(key,"DOTNET_CLI_TELEMETRY_OPTOUT",StringComparison.OrdinalIgnoreCase));
        }
    }
    public void Dispose(){if(disposed)return;disposed=true;pins.Dispose();}
}
