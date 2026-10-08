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
            case 1: {
                byte[] x = Wire.Encode([Success()]); Need(x.Length == 17 && Wire.Decode(x,1)[0].Passed);
                // Cross-language NAS1 vector: admission failure at public caller ordinal 193.
                Need(Convert.ToHexString(Program.ActualStatus(5, 1, 512, 193, 1)) == "4E41533105010002C100000001000000");
                Reject(() => Program.ActualStatus(0, 1, 0, -1, 1));
                Reject(() => Program.ActualStatus(18, 1, 0, -1, 1));
                Reject(() => Program.ActualStatus(5, 8, 0, -1, 1));
                Reject(() => Program.ActualStatus(5, 1, 1024, -1, 1));
                Reject(() => Program.ActualStatus(5, 1, 0, 226, 1));
                Reject(() => Program.ActualStatus(5, 1, 0, -1, 125));
                break;
            }
            case 2: { byte[] x = Wire.Encode([Success(true),Success(true)]); Need(x.Length == 29 && Wire.Decode(x,2).All(r=>r.Passed)); break; }
            case 3: WorkerFailureFrames(); PublicHistoricalChanged(); break;
            case 4: { byte[] x=Wire.Encode([Success()]); Reject(()=>Wire.Decode(x[..^1],1)); Reject(()=>Wire.Decode(x.Concat(new byte[]{0}).ToArray(),1)); break; }
            case 5: { byte[] x=Wire.Encode([Success()]); x[5]=255; Reject(()=>Wire.Decode(x,1)); x=Wire.Encode([Success()]);x[7]|=128;Reject(()=>Wire.Decode(x,1));break; }
            case 6: { SafeResult r=Closed();Need(Wire.Decode(Wire.Encode([r]),1)[0].WriterCloseToCompletionMilliseconds==1000);
                byte[] x=Wire.Encode([r]);x[14]=233;x[15]=3;Reject(()=>Wire.Decode(x,1));break; }
            case 7: { Need(Wire.Decode(Wire.Encode([Success()]),1)[0].WriterCloseToCompletionMilliseconds==-1);
                byte[] x=Wire.Encode([Success()]);x[7]|=16;Reject(()=>Wire.Decode(x,1));break; }
            case 8: { SafeResult r=Closed();r.WriterCloseToExitMilliseconds=1000;r.WriterCloseToCompletionMilliseconds=999;Reject(()=>Wire.Decode(Wire.Encode([r]),1));break; }
            case 9: { byte[] x=Wire.Encode([Closed()]);x[12]=255;x[13]=255;Reject(()=>Wire.Decode(x,1));break; }
            case 10: { byte[] x=Wire.Encode([Success(true),Success(true)]);x[19]&=63;Reject(()=>Wire.Decode(x,2));break; }
            case 11: Reject(()=>CallerRules.DecideFrame([78,67,70,49,(byte)Fault.Native],2,4,1,0));break;
            case 12: PartialWrite(); MechanismDiagnostics(); break;
            default: throw new SafeFailure(Fault.Admission);
        }
    }
    private static void MechanismDiagnostics()
    {
        const string prefix = "Authentication request completed.\nMechanism unavailable at ";
        byte[] good = Encoding.ASCII.GetBytes(prefix + "host_session.\n");
        Need(ProtocolResult.ReadMechanismDiagnostic(good, Outcome.MechanismUnavailable) == MechanismDiagnostic.HostSession);
        Need(ProtocolResult.ReadMechanismDiagnostic(good, Outcome.Success) == MechanismDiagnostic.NotApplicable);
        Need(ProtocolResult.ReadMechanismDiagnostic([], Outcome.MechanismUnavailable) == MechanismDiagnostic.Unavailable);
        foreach (string invalid in new[] { prefix + "SYNTHETIC_PRIVATE@example.test.\n", prefix + "host_session.\nprivate", prefix + "host_session.\r\n" })
            Need(ProtocolResult.ReadMechanismDiagnostic(Encoding.ASCII.GetBytes(invalid), Outcome.MechanismUnavailable) == MechanismDiagnostic.Invalid);
        SafeResult result = new() { Outcome = Outcome.MechanismUnavailable, ProtocolValid = true,
            MechanismDiagnostic = MechanismDiagnostic.HostSession };
        byte[] frame = Wire.Encode([result]);
        Need(frame.Length == 17 && Wire.Decode(frame, 1)[0].MechanismDiagnostic == MechanismDiagnostic.HostSession);
        byte[] legacy = frame[..16]; legacy[3] = (byte)'2';
        Need(Wire.Decode(legacy, 1)[0].MechanismDiagnostic == MechanismDiagnostic.Unavailable);
        frame[16] = 255; Reject(() => Wire.Decode(frame, 1));
        frame = Wire.Encode([Success()]); frame[16] = (byte)MechanismDiagnostic.HostSession;
        Reject(() => Wire.Decode(frame, 1));
        byte[] receipt = SafeReceipt.Project(SafePlan(), "R1", "00000000000040008000000000000000", false,
            result, false, true, true, false, false, 0);
        string text = Encoding.UTF8.GetString(receipt);
        Need(text.Contains("\"productMechanismDiagnostic\":\"HostSession\"", StringComparison.Ordinal));
        Need(!text.Contains("SYNTHETIC_PRIVATE", StringComparison.Ordinal));
    }

    private static void WorkerFailureFrames()
    {
        const string profile = @"C:\fixture\existing\selected-account-profile.json";
        Need(CallerRules.ProfileMatches(profile, profile));
        Need(!CallerRules.ProfileMatches(@"C:\fixture\fresh\selected-account-profile.json", profile));
        byte[] legacy = [78, 67, 70, 49, (byte)Fault.Capture];
        Need(Wire.Failure(legacy) == Fault.Capture && Wire.InspectFailure(legacy).Disposition == WorkerFrameDisposition.Unavailable);
        var checkpoint = new WorkerCheckpoint();
        checkpoint.At(WorkerStage.CallerInventory, 193); checkpoint.Capture(new SafeFailure(Fault.Admission));
        checkpoint.At(WorkerStage.PrivateParse); checkpoint.Capture(new IOException());
        Need(checkpoint.First == new WorkerFailure(Fault.Admission, WorkerStage.CallerInventory, 193));
        byte[] valid = Wire.EncodeFailure(checkpoint.First!.Value);
        Need(Convert.ToHexString(valid) == "4E4346320105C1000000");
        FrameDecision decision = CallerRules.DecideFrame(valid, 1, 1, 1, 0);
        Need(!decision.Passed && decision.Results is null && decision.FirstFault == Fault.Admission &&
            decision.WorkerFrame.Disposition == WorkerFrameDisposition.Validated && decision.WorkerFrame.Failure == checkpoint.First);
        var local = new WorkerFailure(Fault.Admission, WorkerStage.PrivateRead, -1);
        Need(Wire.InspectFailure(Wire.EncodeFailure(local)).Failure == local);
        foreach (byte[] bad in new[] { valid[..^1], valid.Concat(new byte[] { 0 }).ToArray(),
            new byte[] { 78, 67, 70, 51, 1, 5, 193, 0, 0, 0 }, new byte[] { 78, 67, 70, 50, 7, 5, 193, 0, 0, 0 },
            new byte[] { 78, 67, 70, 50, 1, 0, 193, 0, 0, 0 }, new byte[] { 78, 67, 70, 50, 1, 16, 193, 0, 0, 0 },
            new byte[] { 78, 67, 70, 50, 1, 10, 0, 0, 0, 0 }, new byte[] { 78, 67, 70, 50, 1, 5, 194, 0, 0, 0 },
            new byte[] { 78, 67, 70, 50, 1, 6, 197, 0, 0, 0 }, new byte[] { 78, 67, 70, 50, 1, 5, 254, 255, 255, 255 } })
        {
            WorkerFrame invalid = Wire.InspectFailure(bad);
            Need(invalid.Disposition == WorkerFrameDisposition.Invalid && invalid.Failure is null);
            Reject(() => CallerRules.DecideFrame(bad, 1, 1, 1, 0));
        }
        Need(Wire.InspectFailure([]).Disposition == WorkerFrameDisposition.Unavailable);
        Need(Wire.InspectFailure(Wire.Encode([Success()])).Disposition == WorkerFrameDisposition.Unavailable);
        Need(CallerRules.DecideFrame(Wire.Encode([Success()]), 1, 2, 0, 0).Passed);
        Need(Wire.InspectFailure(Wire.Encode([Success()])[..^1]).Disposition == WorkerFrameDisposition.Invalid);
        byte[] receipt = SafeReceipt.Project(SafePlan(), "R1", "00000000000040008000000000000000", false,
            null, false, true, true, false, false, 0, Fault.Admission, decision.WorkerFrame);
        string text = Encoding.UTF8.GetString(receipt);
        Need(text.Contains("\"workerFailureDisposition\":\"validated\"", StringComparison.Ordinal) &&
            text.Contains("\"workerFailure\":{\"fault\":\"Admission\",\"stage\":\"CallerInventory\",\"publicInputOrdinal\":193}", StringComparison.Ordinal));
        Need(receipt.Length <= 4096);
    }
    private static void PublicHistoricalChanged()
    {
        var prepared = new FixtureFileIdentity(uint.MaxValue, ulong.MaxValue, uint.MaxValue,
            long.MaxValue, long.MaxValue, long.MaxValue - 1, 67108864, 1);
        FixtureFileIdentity changed = prepared with { Changed = long.MaxValue };
        Need(FixtureNativePins.PreparedMatches(prepared, prepared));
        Need(!FixtureNativePins.PreparedMatches(changed, prepared));
        Need(FixtureNativePins.PreparedMatches(changed, prepared, true));
        // The production current-snapshot comparison still uses full record equality.
        Need(changed != prepared);
        foreach (FixtureFileIdentity other in new[] { changed with { Volume = 0 }, changed with { Index = 0 },
            changed with { Attributes = 0 }, changed with { Created = 0 }, changed with { Modified = 0 },
            changed with { Length = 0 }, changed with { Links = 2 } })
            Need(!FixtureNativePins.PreparedMatches(other, prepared, true));
        var pins = Enumerable.Range(0, 197).Select(i => new ActualPublicPinEvidence(i, prepared, changed)).ToArray();
        PublicPlan basis = SafePlan();
        var plan = new PublicPlan { SelfImage = basis.SelfImage, ProductImage = basis.ProductImage,
            WorkingDirectory = basis.WorkingDirectory, ReceiptDirectory = basis.ReceiptDirectory,
            ProductSha256 = basis.ProductSha256, CallerSha256 = basis.CallerSha256,
            ProtocolSha256 = basis.ProtocolSha256, ActualPublicPins = pins };
        byte[] receipt = SafeReceipt.Project(plan, "R1", "00000000000040008000000000000000", false,
            Success(), true, true, true, false, false, 0);
        Need(receipt.Length <= 65536);
        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(receipt);
        var evidence = document.RootElement.GetProperty("publicHistoricalChanged");
        Need(evidence.GetProperty("mode").GetString() == "actual-public-historical-changed-v1" &&
            evidence.GetProperty("observedRole").GetString() == "supervisor" && evidence.GetProperty("rows").GetArrayLength() == 197);
        var row = evidence.GetProperty("rows")[196];
        Need(row[0].GetInt32() == 196 && row[1][5].GetInt64() == prepared.Changed && row[2][5].GetInt64() == changed.Changed &&
            row[2][1].GetUInt64() == ulong.MaxValue);
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
