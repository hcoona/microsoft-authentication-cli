using Authentication.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace Authentication.Scenarios;

// Scenario obligations: docs/validation/strategy.md#windows-slice-design-acceptance.
// Every identity and token marker is synthetic. No WAM or service path is present.
[TestClass]
public sealed class SelectedAccountScenarios
{
    private const string PersonalEmail = "personal@example.test";
    private const string WorkEmail = "work@example.test";
    private const string Scope = "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation";
    private static readonly Guid ResourceTenant = new("11111111-2222-3333-4444-555555555555");
    private static readonly Guid ProviderDefaultTenant = new("99999999-8888-7777-6666-555555555555");
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task PersonalAccountReusesItsOwnStateWhenAWorkAccountIsVisible(bool personalFirst)
    {
        var personal = new ProviderAccount(PersonalEmail, new object());
        var work = new ProviderAccount(WorkEmail, new object());
        var provider = new ScenarioProvider(personalFirst ? [personal, work] : [work, personal]);
        var application = Application(provider);

        var outcome = await application.AuthenticateAsync(Request(PersonalEmail));

        Assert.IsNull(outcome.Failure);
        Assert.IsNotNull(outcome.Success);
        Assert.AreEqual(PersonalEmail, outcome.Success.Email);
        Assert.AreEqual("synthetic-personal-access", outcome.Success.AccessToken);
        Assert.IsTrue(outcome.PersistenceUnconfirmed);
    }

    [TestMethod]
    public async Task WorkAccountKeepsTheRequestedResourceTenantWhenAPersonalAccountIsVisible()
    {
        var provider = new ScenarioProvider([
            new ProviderAccount(PersonalEmail, new object()),
            new ProviderAccount(WorkEmail, new object()),
        ]);
        var application = Application(provider);

        var outcome = await application.AuthenticateAsync(Request(WorkEmail, ResourceTenant));

        Assert.IsNull(outcome.Failure);
        Assert.IsNotNull(outcome.Success);
        Assert.AreEqual(WorkEmail, outcome.Success.Email);
        Assert.AreEqual(ResourceTenant, outcome.Success.Tenant);
        Assert.AreEqual("synthetic-work-access", outcome.Success.AccessToken);
    }

    [TestMethod]
    public async Task AmbiguousExactEmailDoesNotAcquireWithEitherAccount()
    {
        var provider = new ScenarioProvider([
            new ProviderAccount(PersonalEmail, new object()),
            new ProviderAccount("PERSONAL@example.test", new object()),
        ]);

        var outcome = await Application(provider).AuthenticateAsync(Request(PersonalEmail));

        Assert.AreEqual(AuthenticationFailure.AccountAmbiguous, outcome.Failure);
        Assert.IsNull(outcome.Success);
        Assert.IsEmpty(provider.Acquisitions);
    }

    [TestMethod]
    public async Task MissingRequestedAccountCannotAcquireAsTheVisibleWorkAccount()
    {
        var provider = new ScenarioProvider([new ProviderAccount(WorkEmail, new object())]);

        var outcome = await Application(provider).AuthenticateAsync(Request(PersonalEmail));

        Assert.AreEqual(AuthenticationFailure.InteractionRequired, outcome.Failure);
        Assert.IsNull(outcome.Success);
        Assert.IsEmpty(provider.Acquisitions);
    }

    [TestMethod]
    public async Task WrongAccountInProviderSuccessCannotExposeAnAccessToken()
    {
        var provider = new ScenarioProvider([new ProviderAccount(PersonalEmail, new object())])
        {
            ReturnedEmail = WorkEmail,
        };

        var outcome = await Application(provider).AuthenticateAsync(Request(PersonalEmail));

        Assert.AreEqual(AuthenticationFailure.IdentityValidationFailed, outcome.Failure);
        Assert.IsNull(outcome.Success);
    }

    [TestMethod]
    public async Task WrongResourceTenantCannotSucceedEvenWhenTheWorkAccountMatches()
    {
        var provider = new ScenarioProvider([new ProviderAccount(WorkEmail, new object())])
        {
            ReturnedTenant = ProviderDefaultTenant,
        };

        var outcome = await Application(provider).AuthenticateAsync(Request(WorkEmail, ResourceTenant));

        Assert.AreEqual(AuthenticationFailure.IdentityValidationFailed, outcome.Failure);
        Assert.IsNull(outcome.Success);
    }

    private static RequestCoordinator Application(IAuthenticationProvider provider) =>
        new(provider, new ScenarioHost());

    private static AuthenticationRequest Request(string email, Guid? tenant = null) =>
        new(email, [Scope], InteractionAllowed: false, tenant);

    private sealed class ScenarioProvider(IReadOnlyList<ProviderAccount> visible) : IAuthenticationProvider
    {
        public string? ReturnedEmail { get; init; }
        public Guid? ReturnedTenant { get; init; }

        public List<ProviderAccount> Acquisitions { get; } = [];

        public Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(visible);

        public Task<TokenCandidate> AcquireSilentAsync(
            AuthenticationRequest request,
            ProviderAccount account,
            Guid operationId,
            CancellationToken cancellationToken)
        {
            Acquisitions.Add(account);
            var token = account.Email == PersonalEmail ? "synthetic-personal-access" : "synthetic-work-access";
            return Task.FromResult(new TokenCandidate(
                token,
                ReturnedEmail ?? account.Email,
                ReturnedTenant ?? request.ExactTenant ?? ProviderDefaultTenant,
                request.Scopes,
                "Bearer",
                Now.AddMinutes(10),
                operationId));
        }
    }

    private sealed class ScenarioHost : IRequestHost
    {
        public TimeProvider Clock { get; } = new ScenarioClock();
    }

    private sealed class ScenarioClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;

        public override long GetTimestamp() => 0;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }
}
