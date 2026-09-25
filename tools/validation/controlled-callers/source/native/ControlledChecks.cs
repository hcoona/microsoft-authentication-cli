// Every decision under check is called by the native caller. No mirrored lifecycle model.
#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Text;
namespace ConfidentialNativeCaller;
internal static class ControlledChecks
{
    internal static void Need(bool value) { if (!value) throw new SafeFailure(Fault.Expectation); }
    internal static void Reject(Action action)
    {
        bool rejected = false;
        try { action(); } catch (SafeFailure) { rejected = true; }
        Need(rejected);
    }
    internal static PublicPlan SafePlan() => new() { SelfImage = @"C:\fixture\caller.exe",
        ProductImage = @"C:\fixture\subject.exe", WorkingDirectory = @"C:\fixture", ReceiptDirectory = @"C:\fixture\receipts",
        ProductSha256 = new string('0',64), CallerSha256 = new string('1',64), ProtocolSha256 = new string('2',64) };
    private static SafeResult Success(bool paired = false) => new() { Outcome = Outcome.Success, Route = Route.Silent,
        Passed = true, ProtocolValid = true, MetadataValid = true, PairProcessOverlapObserved = paired };
    private static SafeResult Closed() => new() { Outcome = Outcome.Cancelled, Passed = true, ProtocolValid = true,
        WriterClosedAfterLiveSample = true, WriterCloseToExitMilliseconds = 999, WriterCloseToCompletionMilliseconds = 1000 };
    internal static void CheckProtocol(ProtocolVector vector)
    {
        SafeResult? result = null; bool rejected = false;
        try { result = ProtocolResult.Validate(vector.Bytes, vector.Exit, vector.Request, vector.Received); }
        catch (SafeFailure) { rejected = true; }
        // Acceptance of the unresolved unpaired-surrogate vector stops the batch.
        // It never becomes an automatically waived or passing parser obligation.
        if (vector.Expect == ParseExpectation.RejectOrStop && !rejected)
            throw new SafeFailure(Fault.Unconfigured);
        Need(vector.Expect == ParseExpectation.Accept ? !rejected && result is { Passed: true, ProtocolValid: true } : rejected);
        if (result is null) return;
        Need(result.Outcome == vector.Request.ExpectedOutcome &&
            (vector.Request.ExpectedRoute == Route.None || result.Route == vector.Request.ExpectedRoute));
        if (vector.Id == "G5-15") Need(result.PersistenceFailed && result.PersistenceUnconfirmed);
        byte[] frame = Wire.Encode([result]);
        SafeResult decoded = Wire.Decode(frame, 1)[0];
        Need(decoded.Outcome == result.Outcome && decoded.Route == result.Route && decoded.Passed == result.Passed);
        byte[] receipt = SafeReceipt.Project(SafePlan(), "fixture", "00000000000040008000000000000000", false,
            result, result.Passed, true, true, false, false, 0);
        string text = Encoding.UTF8.GetString(receipt);
        foreach (string secret in new[] { SyntheticSubjectProgram.SyntheticToken, FixtureAdmission.Email,
            FixtureAdmission.Tenant, FixtureAdmission.Scope, "SYNTHETIC_ADDITIVE", "SYNTHETIC_NESTED", "unknown_synthetic_reason" })
            Need(!text.Contains(secret, StringComparison.Ordinal));
        Need(receipt.Length <= 4096 && !text.Contains("\"noExperimentLive\":true", StringComparison.Ordinal));
    }
    internal static void WireCase(int index)
    {
        switch (index)
        {
            case 1: { byte[] x = Wire.Encode([Success()]); Need(x.Length == 16 && Wire.Decode(x,1)[0].Passed); break; }
            case 2: { byte[] x = Wire.Encode([Success(true),Success(true)]); Need(x.Length == 27 && Wire.Decode(x,2).All(r=>r.Passed)); break; }
            case 3: Need(Wire.Failure([78,67,70,49,(byte)Fault.Capture]) == Fault.Capture); break;
            case 4: { byte[] x=Wire.Encode([Success()]); Reject(()=>Wire.Decode(x[..^1],1)); Reject(()=>Wire.Decode(x.Concat(new byte[]{0}).ToArray(),1)); break; }
            case 5: { byte[] x=Wire.Encode([Success()]); x[5]=255; Reject(()=>Wire.Decode(x,1)); x=Wire.Encode([Success()]);x[7]|=128;Reject(()=>Wire.Decode(x,1));break; }
            case 6: { SafeResult r=Closed();Need(Wire.Decode(Wire.Encode([r]),1)[0].WriterCloseToCompletionMilliseconds==1000);
                byte[] x=Wire.Encode([r]);x[14]=233;x[15]=3;Reject(()=>Wire.Decode(x,1));break; }
            case 7: { Need(Wire.Decode(Wire.Encode([Success()]),1)[0].WriterCloseToCompletionMilliseconds==-1);
                byte[] x=Wire.Encode([Success()]);x[7]|=16;Reject(()=>Wire.Decode(x,1));break; }
            case 8: { SafeResult r=Closed();r.WriterCloseToExitMilliseconds=1000;r.WriterCloseToCompletionMilliseconds=999;Reject(()=>Wire.Decode(Wire.Encode([r]),1));break; }
            case 9: { byte[] x=Wire.Encode([Closed()]);x[12]=255;x[13]=255;Reject(()=>Wire.Decode(x,1));break; }
            case 10: { byte[] x=Wire.Encode([Success(true),Success(true)]);x[18]&=63;Reject(()=>Wire.Decode(x,2));break; }
            case 11: Reject(()=>CallerRules.DecideFrame([78,67,70,49,(byte)Fault.Native],2,4,1,0));break;
            case 12: PartialWrite();break;
            default: throw new SafeFailure(Fault.Admission);
        }
    }
    internal static void SequenceCase(int index)
    {
        // Each row contains at most 16 controlled decisions. All clocks are explicit
        // integer samples; no native child, delay, retry, or random input is used here.
        switch(index)
        {
            case 1: { int c=0;Need(CallerRules.BeginRead(8192,8192,ref c)==1);Need(CallerRules.ReadStep(8192,8192,true,1,0)==ReadDecision.Fail);break; }
            case 2: Need(CallerRules.ReadStep(10,0,true,0,0)==ReadDecision.Continue &&
                CallerRules.ReadStep(10,0,true,3,0)==ReadDecision.Data && CallerRules.ReadStep(10,3,false,0,109)==ReadDecision.Eof);break;
            case 3: Need(!CallerRules.ProductComplete(true,true,false,true,true));break;
            case 4: { Reject(()=>CallerRules.Before(100,100));Need(!CallerRules.SupervisorComplete(true,false,true,true,true,true));
                Need(!CallerRules.TerminalMayPass(true,true));break; }
            case 5: PartialWrite();break;
            case 6: { int c=1024;Reject(()=>CallerRules.BeginRead(0,0,ref c));Need(c==1025);break; }
            case 7: { bool attempted=false;CallerRules.Claim(ref attempted,Fault.Native);Reject(()=>CallerRules.ResumeResult(uint.MaxValue));
                Reject(()=>CallerRules.Claim(ref attempted,Fault.Native));Need(attempted);break; }
            case 8: { long end=CallerRules.CancellationEnd(5000,1000,1000);Need(end==2000);Reject(()=>CallerRules.Before(2001,end));break; }
            case 9: { long end=CallerRules.CancellationEnd(1500,1000,1000);Need(end==1500);
                CallerRules.Before(1499,end);Reject(()=>CallerRules.Before(1500,end));Need(CallerRules.EffectiveDeadline(1400,end)==1400);break; }
            case 10: { var sink=new FailingSink(); bool failed=false;try { SafeReceipt.Persist([1],()=>{},()=>sink,_=>{}); }
                catch(IOException) { failed=true; } Need(failed && sink.Attempts==1);break; }
            case 11: Need(!CallerRules.PairPass(true,false) && CallerRules.PairPass(true,true) && CallerRules.PairPass(false,false));break;
            case 12: { long a=CallerRules.Add(0,5000,1000),b=CallerRules.Add(100,7000,1000);
                Need(a==5000 && b==7100);CallerRules.Before(4999,a);Reject(()=>CallerRules.Before(7100,b));break; }
            case 13: { FrameDecision x=CallerRules.DecideFrame([78,67,70,49,(byte)Fault.Protocol],2,1,1,0);
                Need(!x.Passed && x.FirstFault==Fault.Protocol && x.Results is null);break; }
            case 14: { FrameDecision x=CallerRules.DecideFrame([78,67,70,49,(byte)Fault.Capture],2,2,1,0);
                Need(!x.Passed && x.FirstFault==Fault.Capture && x.Results is null);break; }
            default: throw new SafeFailure(Fault.Admission);
        }
    }
    private static void PartialWrite()
    {
        bool attempted=false;var sink=new FailingSink();bool failed=false;
        try { CallerRules.WriteFrame(ref attempted,[78,67,70,49,3],()=>sink); } catch(IOException){failed=true;}
        Reject(()=>CallerRules.WriteFrame(ref attempted,[78,67,70,49,3],()=>sink));
        Need(failed && attempted && sink.Attempts==1 && sink.BytesBeforeFailure==2);
    }
    private sealed class FailingSink : Stream
    {
        internal int Attempts,BytesBeforeFailure;
        public override bool CanRead=>false;public override bool CanSeek=>false;public override bool CanWrite=>true;
        public override long Length=>BytesBeforeFailure;public override long Position{get=>BytesBeforeFailure;set=>throw new NotSupportedException();}
        public override void Write(byte[] b,int o,int c)=>Write(b.AsSpan(o,c));
        public override void Write(ReadOnlySpan<byte> b){Attempts++;BytesBeforeFailure=Math.Min(2,b.Length);throw new IOException();}
        public override void Flush(){}public override int Read(byte[] b,int o,int c)=>throw new NotSupportedException();
        public override long Seek(long o,SeekOrigin s)=>throw new NotSupportedException();public override void SetLength(long n)=>throw new NotSupportedException();
    }
}
