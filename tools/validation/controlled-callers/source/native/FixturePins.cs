// Concrete synthetic routing, native admission, and receipt validation.
// Concrete admission holds only exact public synthetic files; it performs no account discovery.
#nullable enable
using System;
using System.IO;
using System.Text.Json;
namespace ConfidentialNativeCaller;
internal static class FixturePins
{
    private static AcceptedFixtureInputs? inputs;
    private static bool initializationAttempted;
    private static AcceptedFixtureInputs Inputs => inputs ?? throw new SafeFailure(Fault.Unconfigured);
    internal static IDisposable InitializeBatch(string path,string sha,long workEnd)
    {
        PrivateRequest.Require(FixtureAdmission.ExecutionAdmitted);
        CallerRules.Claim(ref initializationAttempted,Fault.Admission);
        inputs=new AcceptedFixtureInputs(path,sha,workEnd);
        try { return inputs.HoldBatch(); } catch { inputs.Dispose();throw; }
    }
    internal static int RunRole(string[] args,long entry,bool worker)
    {
        FixtureDiagnostics.At(FixtureStage.RoleAdmission,0);
        PrivateRequest.Require(FixtureAdmission.ExecutionAdmitted);
        PrivateRequest.Require(args.Length==7 && args[0]==(worker?"--fixture-worker":"--fixture-supervisor") &&
            Enum.TryParse(args[1],false,out Group group) && group.ToString()==args[1]);
        group=Enum.Parse<Group>(args[1],false);
        PrivateRequest.Require(long.TryParse(args[5],System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture,out long batchEnd));
        PrivateRequest.Require(long.TryParse(args[6],System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture,out long boundEnd));
        PrivateRequest.Require(boundEnd>System.Diagnostics.Stopwatch.GetTimestamp() && boundEnd<=batchEnd);
        CallerRules.Claim(ref initializationAttempted,Fault.Admission);
        inputs=new AcceptedFixtureInputs(args[3],args[4],batchEnd,boundEnd);
        try
        {
            PublicPlan plan=LoadPlan(group,args[2]);
            using IDisposable held=inputs.HoldRoleBound(plan,group,args[2],worker,boundEnd);
            return worker?Program.Work(plan,group,boundEnd,true):Program.Supervise(plan,group,args[2],entry,true,boundEnd);
        }
        finally { inputs.Dispose(); }
    }
    internal static string[] RoleArguments(Group group,string role,long boundEnd) => Inputs.RoleArguments(group,role,boundEnd);
    internal static IDisposable BindCreated(Group group,string role,Child child,long boundEnd) => Inputs.BindCreated(group,role,child,boundEnd);
    private static string Id(Group group) => group switch {
        Group.R5Pair => "N1", Group.R7 => "N2", Group.R1 => "N3", _ => throw new SafeFailure(Fault.Admission) };
    internal static PublicPlan LoadPlan(Group group,string nonce)
    {
        string id=Id(group);PrivateRequest.Require(nonce==Inputs.Nonce(id));return Inputs.Plan(id);
    }
    internal static PublicPlan BatchPlan(string id) => Inputs.Plan(id);
    internal static string BatchNonce(string id) => Inputs.Nonce(id);
    internal static void ValidateAndRecordCase(string id,int exit,long elapsedMilliseconds)
    {
        PrivateRequest.Require(id is "N1" or "N2" or "N3" && elapsedMilliseconds is >=0 and <145000 && exit==(id=="N3"?1:0));
        PublicPlan plan=Inputs.Plan(id);string nonce=Inputs.Nonce(id);
        string[] slots=id=="N1"?["R5a","R5b"]:id=="N2"?["R7"]:["R1"];
        foreach(string slot in slots)
            foreach(bool reservation in new[]{true,false})
            {
                string leaf=slot+(reservation?"-reservation.json":"-terminal.json");
                byte[] bytes=Inputs.ReadHeldReceipt(id,leaf,4096);
                FixtureReceiptRules.Validate(bytes,plan,id,slot,nonce,reservation);
            }
        Inputs.PublishExclusive(id+"-case.json",FixtureReceiptRules.CaseRecord(id,exit,checked((int)elapsedMilliseconds)));
    }
    internal static void RecordBatch(bool passed,int pureRows,int nativeCases) =>
        Inputs.PublishExclusive("batch.json",FixtureReceiptRules.BatchRecord(passed,pureRows,nativeCases,Inputs.NativeBaselineSha256,FixtureDiagnostics.First));
}

internal enum FixtureStage
{
    BatchAdmission, PureChecks, PrepareCase, CreateSupervisor, BindSupervisor,
    ResumeSupervisor, WaitSupervisor, SupervisorExit, ValidateCase, RoleAdmission,
    Reservation, CreateWorker, BindWorker, ResumeWorker, WaitWorker, ValidateWorker,
    TerminalReceipt, BatchReceipt
}

// One failure on existing synthetic channels. No exception strings, new files, or observations.
internal sealed record FixtureFailure(FixtureStage Stage,Fault Fault,FixtureCheckSource CheckSource,
    int CheckLine,FixturePinPhase PinPhase,int InputOrdinal,int CaseOrdinal,uint? SupervisorExit,int? OpenError)
{
    internal void Write(Utf8JsonWriter json)
    {
        json.WriteStartObject();json.WriteNumber("stage",(int)Stage);json.WriteNumber("fault",(int)Fault);
        json.WriteNumber("checkSource",(int)CheckSource);json.WriteNumber("checkLine",CheckLine);
        json.WriteNumber("pinPhase",(int)PinPhase);json.WriteNumber("inputOrdinal",InputOrdinal);
        json.WriteNumber("caseOrdinal",CaseOrdinal);
        if(SupervisorExit is uint exit)json.WriteNumber("supervisorExit",exit);else json.WriteNull("supervisorExit");
        if(OpenError is int error)json.WriteNumber("openError",error);else json.WriteNull("openError");
        json.WriteEndObject();
    }
    internal byte[] Encode()
    {
        using var memory=new MemoryStream();using(var json=new Utf8JsonWriter(memory)){Write(json);json.Flush();}
        PrivateRequest.Require(memory.Length<=1024);return memory.ToArray();
    }
    internal static FixtureFailure Parse(ReadOnlyMemory<byte> bytes)
    {
        PrivateRequest.Require(bytes.Length is >0 and <=1024);
        using JsonDocument doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=2});
        JsonElement value=doc.RootElement;
        var result=new FixtureFailure((FixtureStage)value.GetProperty("stage").GetInt32(),
            (Fault)value.GetProperty("fault").GetInt32(),(FixtureCheckSource)value.GetProperty("checkSource").GetInt32(),
            value.GetProperty("checkLine").GetInt32(),(FixturePinPhase)value.GetProperty("pinPhase").GetInt32(),
            value.GetProperty("inputOrdinal").GetInt32(),value.GetProperty("caseOrdinal").GetInt32(),
            value.GetProperty("supervisorExit").ValueKind==JsonValueKind.Null?null:value.GetProperty("supervisorExit").GetUInt32(),
            value.GetProperty("openError").ValueKind==JsonValueKind.Null?null:value.GetProperty("openError").GetInt32());
        PrivateRequest.Require(Enum.IsDefined(result.Stage) && Enum.IsDefined(result.Fault) &&
            Enum.IsDefined(result.CheckSource) && Enum.IsDefined(result.PinPhase) && result.CheckLine is >=0 and <=65535 &&
            result.InputOrdinal is >=-1 and <=202 && result.CaseOrdinal is >=0 and <=3 &&
            bytes.Span.SequenceEqual(result.Encode()));
        return result;
    }
}

internal static class FixtureDiagnostics
{
    private static FixtureStage stage;
    private static int inputOrdinal=-1;
    internal static int CaseOrdinal;
    internal static uint? SupervisorExit;
    internal static FixtureFailure? First { get; private set; }
    internal static void At(FixtureStage value,int input=-1){stage=value;inputOrdinal=input;}
    internal static void Input(int ordinal){inputOrdinal=ordinal;}
    internal static void RejectBaseline(int line,int input)
    {
        // Only the known supervisor baseline rejection reaches this failure-only path.
        // Diagnostic read failures retain that rejection; they never become scenario evidence.
        First??=new(stage,Fault.Admission,FixtureCheckSource.Admission,line,FixturePinPhase.None,
            input,CaseOrdinal,SupervisorExit,null);
        throw new SafeFailure(Fault.Admission);
    }
    internal static void Capture(Exception caught)
    {
        First??=new(stage,caught is SafeFailure safe?safe.Fault:Fault.Native,
            FixtureNativePins.FailedCheckSource,FixtureNativePins.FailedCheckLine,FixtureNativePins.PinPhase,
            inputOrdinal,CaseOrdinal,SupervisorExit,FixtureNativePins.OpenError);
    }
    internal static void RejectSupervisor(ReadOnlyMemory<byte> bytes)
    {
        FixtureFailure remote=FixtureFailure.Parse(bytes);
        First??=remote with { CaseOrdinal=CaseOrdinal,SupervisorExit=SupervisorExit };
        throw new SafeFailure(Fault.Expectation);
    }
}
