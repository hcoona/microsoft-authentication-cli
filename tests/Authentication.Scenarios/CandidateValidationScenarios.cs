using Authentication.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Scenarios;

[TestClass]
public sealed class CandidateValidationScenarios
{
    private const string Email = "selected@example.test";
    private const string Scope = "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation";
    private static readonly Guid Tenant = new("11111111-2222-3333-4444-555555555555");
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);

    [TestMethod]
    [DataRow("empty-token")]
    [DataRow("missing-email")]
    [DataRow("missing-tenant")]
    [DataRow("missing-token-type")]
    [DataRow("expired")]
    [DataRow("expires-now")]
    [DataRow("missing-scope")]
    [DataRow("scope-case-mismatch")]
    [DataRow("different-operation")]
    public async Task IncompleteOrUnrelatedProviderSuccessCannotExposeAnAccessToken(string defect)
    {
        var provider = new CandidateProvider(candidate => defect switch
        {
            "empty-token" => candidate with { AccessToken = "" },
            "missing-email" => candidate with { Email = null },
            "missing-tenant" => candidate with { Tenant = null },
            "missing-token-type" => candidate with { TokenType = "" },
            "expired" => candidate with { ExpiresOn = Now.AddTicks(-1) },
            "expires-now" => candidate with { ExpiresOn = Now },
            "missing-scope" => candidate with { Scopes = [] },
            "scope-case-mismatch" => candidate with { Scopes = [Scope.ToUpperInvariant()] },
            "different-operation" => candidate with { OperationId = Guid.Empty },
            _ => throw new InvalidOperationException("Unknown synthetic defect."),
        });

        var outcome = await new RequestCoordinator(provider, new ScenarioHost())
            .AuthenticateAsync(new AuthenticationRequest(Email, [Scope], false, null));

        Assert.AreEqual(AuthenticationFailure.IdentityValidationFailed, outcome.Failure);
        Assert.IsNull(outcome.Success);
    }

    [TestMethod]
    public async Task ValidSuccessPreservesMetadataWithoutAnExtraMinimumLifetime()
    {
        var provider = new CandidateProvider(candidate => candidate with
        {
            Email = "SELECTED@example.test",
            ExpiresOn = Now.AddTicks(1),
            Scopes = [Scope, "499b84ac-1321-427f-aa17-267ca6975798/extra_permission"],
        });

        var outcome = await new RequestCoordinator(provider, new ScenarioHost())
            .AuthenticateAsync(new AuthenticationRequest(Email, [Scope], false, null));

        Assert.IsNull(outcome.Failure);
        Assert.IsNotNull(outcome.Success);
        Assert.AreEqual("SELECTED@example.test", outcome.Success.Email);
        Assert.AreEqual(Now.AddTicks(1), outcome.Success.ExpiresOn);
        Assert.AreEqual(Tenant, outcome.Success.Tenant);
        Assert.AreEqual("Bearer", outcome.Success.TokenType);
        Assert.AreEqual("synthetic-selected-access", outcome.Success.AccessToken);
        CollectionAssert.AreEqual(
            new[] { Scope, "499b84ac-1321-427f-aa17-267ca6975798/extra_permission" },
            outcome.Success.Scopes.ToArray());
        Assert.IsTrue(outcome.PersistenceUnconfirmed);
    }

    private sealed class CandidateProvider(Func<TokenCandidate, TokenCandidate> transform)
        : IAuthenticationProvider
    {
        public Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ProviderAccount>>([new(Email, new object())]);

        public Task<TokenCandidate> AcquireSilentAsync(
            AuthenticationRequest request,
            ProviderAccount account,
            Guid operationId,
            CancellationToken cancellationToken) => Task.FromResult(transform(new TokenCandidate(
                "synthetic-selected-access", Email, Tenant, [Scope], "Bearer", Now.AddMinutes(10), operationId)));
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
