using Authentication.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Scenarios;

[TestClass]
public sealed class DefaultPermissionScenarios
{
    private const string Email = "selected@example.test";
    private const string Resource = "499b84ac-1321-427f-aa17-267ca6975798";
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public async Task DefaultPermissionsAcceptExpandedGrantsFromTheSameOperation()
    {
        var application = new RequestCoordinator(new ExpandedPermissionProvider(), new ScenarioHost());

        var outcome = await application.AuthenticateAsync(
            new AuthenticationRequest(Email, [Resource + "/.default"], false, null));

        Assert.IsNull(outcome.Failure);
        Assert.IsNotNull(outcome.Success);
        CollectionAssert.AreEqual(new[] { Resource + "/user_impersonation" }, outcome.Success.Scopes.ToArray());
    }

    [TestMethod]
    public async Task DefaultPermissionsCannotAcceptAnUnrelatedOperation()
    {
        var application = new RequestCoordinator(
            new ExpandedPermissionProvider { UnrelatedOperation = true }, new ScenarioHost());

        var outcome = await application.AuthenticateAsync(
            new AuthenticationRequest(Email, [Resource + "/.default"], false, null));

        Assert.AreEqual(AuthenticationFailure.IdentityValidationFailed, outcome.Failure);
        Assert.IsNull(outcome.Success);
    }

    private sealed class ExpandedPermissionProvider : IAuthenticationProvider
    {
        public bool UnrelatedOperation { get; init; }

        public Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ProviderAccount>>([new(Email, new object())]);

        public Task<TokenCandidate> AcquireSilentAsync(
            AuthenticationRequest request,
            ProviderAccount account,
            Guid operationId,
            CancellationToken cancellationToken) => Task.FromResult(new TokenCandidate(
                "synthetic-default-access", Email, new Guid("11111111-2222-3333-4444-555555555555"),
                [Resource + "/user_impersonation"], "Bearer", Now.AddMinutes(10),
                UnrelatedOperation ? Guid.Empty : operationId));
    }

    private sealed class ScenarioHost : IRequestHost
    {
        public TimeProvider Clock { get; } = new ScenarioClock();
    }

    private sealed class ScenarioClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
