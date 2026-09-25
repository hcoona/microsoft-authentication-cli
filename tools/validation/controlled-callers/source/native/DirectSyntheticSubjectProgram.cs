#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
namespace ConfidentialNativeCaller;
internal static class DirectSyntheticSubjectProgram
{
    private static readonly bool ExecutionAdmitted=false;
    internal const string DirectScope="12345678-1234-4abc-8abc-1234567890ab/read";
    internal static string[] Arguments(bool close)
    {
        string[] common=["authenticate","--protocol","1","--profile",@"C:\synthetic\profile.json",
            "--account-email","fixture@example.invalid","--interaction","non-interactive-only","--tenant",FixtureAdmission.Tenant,
            "--timeout-seconds","5","--telemetry","off","--scope",DirectScope];
        return common.Concat(close?new[]{"--cancel-on-stdin-close","--synthetic-direct","D2"}:new[]{"--synthetic-direct","D1"}).ToArray();
    }
    public static int Main(string[] args)
    {
        if(!ExecutionAdmitted)return 125;
        try
        {
            bool close=args.SequenceEqual(Arguments(true),StringComparer.Ordinal);
            PrivateRequest.Require(close || args.SequenceEqual(Arguments(false),StringComparer.Ordinal));
            using Stream output=Console.OpenStandardOutput();
            if(close)
            {
                using Stream input=Console.OpenStandardInput();PrivateRequest.Require(input.ReadByte()==-1);
                output.Write(Encoding.UTF8.GetBytes("{\"protocol\":1,\"outcome\":\"cancelled\",\"reason\":\"synthetic_closed\"}\n"));
                output.Flush();return 1;
            }
            byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(new { protocol=1,outcome="success",
                accessToken=SyntheticSubjectProgram.SyntheticToken,tokenType="Synthetic",expiresOn=DateTimeOffset.UtcNow.AddMinutes(1),
                accountEmail="fixture@example.invalid",tenantId=FixtureAdmission.Tenant,
                authority="https://login.microsoftonline.com/"+FixtureAdmission.Tenant,scopes=new[]{DirectScope},
                mechanism="wam",interaction="silent",warnings=new[]{"persistence_unconfirmed"} });
            output.Write(bytes);output.WriteByte(10);output.Flush();return 0;
        }
        catch{return 1;}
    }
}
