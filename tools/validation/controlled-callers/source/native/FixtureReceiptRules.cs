#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
namespace ConfidentialNativeCaller;
internal static class FixtureReceiptRules
{
    internal static void Validate(byte[] bytes,PublicPlan plan,string id,string slot,string nonce,bool reservation)
    {
        PrivateRequest.Require(bytes.Length is >0 and <=4096 && bytes[^1]==10);
        using JsonDocument doc=JsonDocument.Parse(bytes);
        JsonElement root=doc.RootElement;PrivateRequest.Require(root.ValueKind==JsonValueKind.Object);
        var names=new HashSet<string>(StringComparer.Ordinal);
        foreach(JsonProperty p in root.EnumerateObject())PrivateRequest.Require(names.Add(p.Name));
        int elapsed=Number(root,"elapsedMilliseconds",0,145000);
        SafeResult? result=null;
        if(!reservation && id!="N3")
        {
            result=new SafeResult {
                Outcome=id=="N1"?Outcome.Success:Outcome.Cancelled, Route=id=="N1"?Route.Silent:Route.None,
                Passed=true, ProtocolValid=true, MetadataValid=id=="N1", PairProcessOverlapObserved=id=="N1",
                WriterClosedAfterLiveSample=id=="N2", ElapsedMilliseconds=Number(root,"productElapsedMilliseconds",0,135000),
                WriterCloseToExitMilliseconds=id=="N2"?Number(root,"writerCloseToExitMilliseconds",0,1000):-1,
                WriterCloseToCompletionMilliseconds=id=="N2"?Number(root,"writerCloseToCompletionMilliseconds",0,1000):-1
            };
            PrivateRequest.Require(result.WriterCloseToCompletionMilliseconds>=result.WriterCloseToExitMilliseconds);
        }
        byte[] expected=SafeReceipt.Project(plan,slot,nonce,reservation,result,!reservation && id!="N3",
            !reservation,!reservation,false,false,elapsed,!reservation && id=="N3"?Fault.Capture:null);
        // Exact canonical serialization rejects extra members and arbitrary strings.
        // Only bounded timings are extracted; no raw source string enters a new record.
        PrivateRequest.Require(bytes.AsSpan().SequenceEqual(expected));
    }
    private static int Number(JsonElement root,string key,int min,int max)
    {
        PrivateRequest.Require(root.TryGetProperty(key,out JsonElement field) && field.ValueKind==JsonValueKind.Number);
        PrivateRequest.Require(field.TryGetInt32(out int value) && value>=min && value<=max);return value;
    }
    internal static byte[] CaseRecord(string id,int exit,int elapsed) => Record(json=>{
        json.WriteString("schema","synthetic-caller-case-v1");json.WriteString("case",id);json.WriteBoolean("passed",true);
        json.WriteNumber("exit",exit);json.WriteNumber("elapsedMilliseconds",elapsed);json.WriteBoolean("noExperimentLive",false);
    });
    internal static byte[] BatchRecord(bool passed,int rows,int cases,string nativeBaselineSha256)
    {
        PrivateRequest.Require(rows is >=0 and <=84 && cases is >=0 and <=3 && (!passed || rows==84 && cases==3));
        return Record(json=>{json.WriteString("schema","synthetic-caller-batch-v1");json.WriteBoolean("passed",passed);
            json.WriteString("nativeBaselineSha256",nativeBaselineSha256);
            json.WriteNumber("completedPureRows",rows);json.WriteNumber("completedNativeCases",cases);json.WriteBoolean("noExperimentLive",false);});
    }
    private static byte[] Record(Action<Utf8JsonWriter> content)
    {
        using var memory=new MemoryStream();using(var json=new Utf8JsonWriter(memory))
        {json.WriteStartObject();content(json);json.WriteEndObject();json.Flush();}
        memory.WriteByte(10);PrivateRequest.Require(memory.Length<=4096);return memory.ToArray();
    }
}
