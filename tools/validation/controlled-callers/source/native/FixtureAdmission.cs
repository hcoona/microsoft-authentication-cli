// Synthetic-only adapter. Real admission uses separate closed public/private controls.
#nullable enable
using System;
using System.Linq;
namespace ConfidentialNativeCaller;
internal static class FixtureAdmission
{
    internal static readonly bool ExecutionAdmitted = false;
    internal const string Email = "\u00e9.fixture@example.invalid";
    internal const string Tenant = "12345678-1234-4abc-8abc-1234567890ab";
    internal const string Scope = "https://fixture.invalid/read";
    internal static readonly string[] QuoteVector = ["", "two words", "quoted\"value", "Unicode-\u6c34", "tail\\"];
    internal static PrivateRequest Request(Outcome outcome = Outcome.Success, int timeout = 5, bool lifetime = false) => new()
    {
        ProfilePath = @"C:\synthetic only\profile.json", Email = Email, Scopes = [Scope], TenantArgument = Tenant,
        ExactResultTenant = Guid.ParseExact(Tenant, "D"), TimeoutSeconds = timeout,
        LifetimePipe = lifetime, CloseWriterAfterMilliseconds = lifetime ? 100 : null,
        RequireCloseAfterLiveSample = lifetime, ExpectedOutcome = outcome,
        ExpectedRoute = outcome == Outcome.Success ? Route.Silent : Route.None
    };
    internal static PrivateRequest[] Requests(Group group) => group switch
    {
        Group.R5Pair => [Request(timeout: 5), Request(timeout: 7)],
        Group.R7 => [Request(Outcome.Cancelled, 5, true)],
        Group.R1 => [Request()],
        _ => throw new SafeFailure(Fault.Admission)
    };
    internal static string[] Arguments(Group group, PrivateRequest request) =>
        request.Arguments().Concat(new[] { "--synthetic-role", group switch {
            Group.R5Pair => "N1", Group.R7 => "N2", Group.R1 => "N3", _ => throw new SafeFailure(Fault.Admission) } })
            .Concat(QuoteVector).ToArray();
}
