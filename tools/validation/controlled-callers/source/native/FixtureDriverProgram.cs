#nullable enable
using System;
using System.Diagnostics;
using System.Globalization;
using System.Threading;
namespace ConfidentialNativeCaller;
internal static class FixtureDriverProgram
{
    private static readonly bool ExecutionAdmitted = false;
    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted) return 125;
        int rows=0,cases=0;bool passed=false;IDisposable? admission=null;
        long began=Stopwatch.GetTimestamp(),workEnd=CallerRules.Add(began,300000,Stopwatch.Frequency);
        long terminalEnd=CallerRules.Add(workEnd,10000,Stopwatch.Frequency);
        try
        {
            PrivateRequest.Require(args.Length==2 && OperatingSystem.IsWindows());
            admission=FixturePins.InitializeBatch(args[0],args[1],workEnd);
            long pureEnd=Math.Min(workEnd,CallerRules.Add(Stopwatch.GetTimestamp(),10000,Stopwatch.Frequency));
            foreach(ProtocolVector vector in ProtocolVectors.All())
            { CallerRules.Before(Stopwatch.GetTimestamp(),pureEnd);ControlledChecks.CheckProtocol(vector);rows++; }
            for(int i=1;i<=12;i++){CallerRules.Before(Stopwatch.GetTimestamp(),pureEnd);ControlledChecks.WireCase(i);rows++;}
            for(int i=1;i<=14;i++){CallerRules.Before(Stopwatch.GetTimestamp(),pureEnd);ControlledChecks.SequenceCase(i);rows++;}
            PrivateRequest.Require(rows==84);
            foreach(string id in new[]{"N1","N2","N3"})
            {
                CallerRules.Before(Stopwatch.GetTimestamp(),workEnd);
                PublicPlan plan=FixturePins.BatchPlan(id);string nonce=FixturePins.BatchNonce(id);
                Group group=id=="N1"?Group.R5Pair:id=="N2"?Group.R7:Group.R1;
                long start=Stopwatch.GetTimestamp();
                long caseEnd=Math.Min(workEnd,CallerRules.Add(start,145000,Stopwatch.Frequency));
                using var input=new InputPipe(false);using var output=new MemoryPipe(1);using var error=new MemoryPipe(1);
                using Child caller=Native.StartSuspended(plan.SelfImage,FixturePins.RoleArguments(group,"supervisor",caseEnd),
                    plan.WorkingDirectory,input,output,error,null);
                using IDisposable identity=FixturePins.BindCreated(group,"supervisor",caller,caseEnd);
                CallerRules.Before(Stopwatch.GetTimestamp(),caseEnd);caller.ResumeOnce();
                while(true)
                {
                    CallerRules.Before(Stopwatch.GetTimestamp(),caseEnd);
                    PrivateRequest.Require(!output.Failed && !error.Failed);
                    if(CallerRules.ProductComplete(caller.Exited(),output.Done,output.Eof,error.Done,error.Eof))break;
                    Thread.Sleep(10);
                }
                PrivateRequest.Require(output.Bytes.Length==0 && error.Bytes.Length==0);
                uint exit=caller.ExitCode();PrivateRequest.Require(exit==(id=="N3"?1u:0u));
                // Exact held receipt reads check all reservations/terminals, Job-zero,
                // case-specific overlap/close/NCF1 expectation, and marker omission.
                // The concrete adapter retains native pins throughout these bounded reads.
                FixturePins.ValidateAndRecordCase(id,checked((int)exit),
                    checked((Stopwatch.GetTimestamp()-start)*1000/Stopwatch.Frequency));cases++;
            }
            CallerRules.Before(Stopwatch.GetTimestamp(),workEnd);passed=cases==3;
        }
        catch { passed=false; }
        try { CallerRules.Before(Stopwatch.GetTimestamp(),terminalEnd);FixturePins.RecordBatch(passed,rows,cases); }
        catch { return 1; }
        finally { admission?.Dispose(); }
        return passed?0:1;
    }
}
