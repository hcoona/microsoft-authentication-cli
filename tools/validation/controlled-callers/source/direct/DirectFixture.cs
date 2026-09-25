// Inert exact synthetic direct request binding. No private input is loaded.
#nullable enable
using System;
using System.Linq;
namespace ConfidentialWsl;
internal static class DirectFixture
{
    internal const string Tenant="12345678-1234-4abc-8abc-1234567890ab";
    internal const string Scope=Tenant+"/read";
    internal static PrivateExpectation Expectation(Slot slot, bool soleLaunchAccepted)
    {
        PrivateExpectation.Check(DirectRoles.Fixture(slot));
        string[] common=["authenticate","--protocol","1","--profile",@"C:\synthetic\profile.json",
            "--account-email","fixture@example.invalid","--interaction","non-interactive-only",
            "--tenant",Tenant,"--timeout-seconds","5","--telemetry","off","--scope",Scope];
        string[] suffix=slot==Slot.D2 ? ["--cancel-on-stdin-close","--synthetic-direct","D2"] :
            ["--synthetic-direct","D1"];
        return new PrivateExpectation { Arguments=common.Concat(suffix).ToArray(),
            SoleLaunchIdentityPremiseAccepted=soleLaunchAccepted,TargetedStopPremiseAccepted=false };
    }
}
