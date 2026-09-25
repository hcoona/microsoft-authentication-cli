// Concrete synthetic routing, native admission, and receipt validation.
// Concrete admission holds only exact public synthetic files; it performs no account discovery.
#nullable enable
using System;
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
        Inputs.PublishExclusive("batch.json",FixtureReceiptRules.BatchRecord(passed,pureRows,nativeCases,Inputs.NativeBaselineSha256));
}
