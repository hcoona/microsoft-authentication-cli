#nullable enable
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
namespace ConfidentialNativeCaller;
internal static class SyntheticSubjectProgram
{
    private static readonly bool ExecutionAdmitted = false;
    internal const string SyntheticToken = "SYNTHETIC_TOKEN_NEVER_A_CREDENTIAL";
    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted) return 125;
        try
        {
            int roleAt = Array.IndexOf(args, "--synthetic-role");
            PrivateRequest.Require(roleAt >= 0 && roleAt + 7 == args.Length);
            string role = args[roleAt + 1];
            Group group = role switch { "N1" => Group.R5Pair, "N2" => Group.R7, "N3" => Group.R1,
                _ => throw new SafeFailure(Fault.Admission) };
            bool same = FixtureAdmission.Requests(group).Any(request =>
                FixtureAdmission.Arguments(group, request).SequenceEqual(args, StringComparer.Ordinal));
            PrivateRequest.Require(same);
            long end = CallerRules.Add(Stopwatch.GetTimestamp(), 2500, Stopwatch.Frequency);
            using Stream output = Console.OpenStandardOutput();
            if (role == "N3")
            {
                // Exactly one byte beyond the production capture cap, then natural exit.
                byte[] bytes = Enumerable.Repeat((byte)'S', 1048577).ToArray();
                output.Write(bytes); output.Flush(); return 0;
            }
            if (role == "N2")
            {
                using Stream input = Console.OpenStandardInput();
                // A blocked read is bounded by the caller's original product deadline
                // and enclosing Job. The only intended writer belongs to that caller.
                PrivateRequest.Require(input.ReadByte() == -1);
                output.Write(Encoding.UTF8.GetBytes("{\"protocol\":1,\"outcome\":\"cancelled\",\"reason\":\"fixture_closed\"}\n"));
                output.Flush(); return 1;
            }
            // A finite hold makes positive original-handle pair overlap observable.
            // If creation is unusually slow, lack of overlap fails without retry.
            while (Stopwatch.GetTimestamp() < end) Thread.Sleep(10);
            byte[] result = JsonSerializer.SerializeToUtf8Bytes(new {
                protocol = 1, outcome = "success", accessToken = SyntheticToken, tokenType = "Synthetic",
                expiresOn = DateTimeOffset.UtcNow.AddMinutes(1), accountEmail = FixtureAdmission.Email,
                tenantId = FixtureAdmission.Tenant, authority = "https://login.microsoftonline.com/" + FixtureAdmission.Tenant,
                scopes = new[] { FixtureAdmission.Scope }, mechanism = "wam", interaction = "silent", warnings = Array.Empty<string>() });
            output.Write(result); output.WriteByte(10); output.Flush(); return 0;
        }
        catch { return 1; }
    }
}
