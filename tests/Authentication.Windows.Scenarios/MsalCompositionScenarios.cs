using System.Text;
using System.Text.Json.Nodes;
using Authentication.Core;
using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Windows.Scenarios;

// Execute the real adapter and coordinator with a session that cannot reach MSAL
// construction, native libraries, account state, network, windows, or child processes.
[TestClass]
public sealed class MsalCompositionScenarios
{
    private const string Email = "personal@example.test";
    private const string Scope = "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation";
    private const string Tenant = "11111111-2222-3333-4444-555555555555";
    private const string MsaTenant = "9188040d-6c67-4c5b-b112-36a304b66dad";
    private const string TransferTenant = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";
    private const string PrivateMarker = "SYNTHETIC-MSAL-COMPOSITION-PRIVATE";
    private static readonly DateTimeOffset Now = new(2026, 9, 15, 0, 0, 0, TimeSpan.Zero);
    private static readonly Guid ObservedCorrelation = new("33333333-4444-5555-6666-777777777777");

    [TestMethod]
    public Task OrdinaryMultitenantProfileUsesCommon() =>
        VerifyRouteAsync(false, "common", false, "common", "common");

    [TestMethod]
    public Task FixedWorkProfileUsesItsTenant() =>
        VerifyRouteAsync(false, "fixed", false, Tenant, Tenant);

    [TestMethod]
    public Task ExplicitWorkTenantOverridesCommon() =>
        VerifyRouteAsync(false, "explicit", false, Tenant, Tenant);

    [TestMethod]
    public Task LegacyPersonalAccountUsesTheTransferTenant() =>
        VerifyRouteAsync(true, "common", true, "organizations", TransferTenant);

    [TestMethod]
    public Task LegacyWorkAccountRetainsOrganizations() =>
        VerifyRouteAsync(true, "common", false, "organizations", "organizations");

    [TestMethod]
    public Task ExplicitResourceTenantWinsOverLegacyPersonalRouting() =>
        VerifyRouteAsync(true, "explicit", true, Tenant, Tenant);

    private static async Task VerifyRouteAsync(bool legacy, string tenantPolicy,
        bool personalAccount, string initialTenant, string silentTenant)
    {
        using var scene = new Scene(legacy, tenantPolicy, personalAccount);
        var outcome = await scene.RunAsync();
        Assert.IsNotNull(outcome.Success, "The admitted selected-account journey must succeed.");
        Assert.IsNotNull(scene.Settings);
        Assert.AreEqual(scene.Profile.ClientId, scene.Settings.ClientId);
        Assert.AreEqual("https://login.microsoftonline.com/" + initialTenant, scene.Settings.Authority);
        Assert.AreEqual("ms-appx-web://microsoft.aad.brokerplugin/" + scene.Profile.ClientId,
            scene.Settings.RedirectUri);
        Assert.IsTrue(scene.Settings.ListOperatingSystemAccounts);
        Assert.AreEqual(legacy, scene.Settings.MsaPassthrough);
        Assert.AreSame(scene, scene.HttpFactory);
        Assert.AreEqual(1, scene.Initializations);
        Assert.AreEqual(1, scene.Discoveries);
        Assert.AreEqual(1, scene.Silent.Count);
        Assert.AreSame(scene.Selected, scene.Silent[0].Account, "The nonmatching first account must not be selected.");
        Assert.AreEqual(silentTenant, scene.Silent[0].Tenant);
        CollectionAssert.AreEqual(new[] { Scope }, scene.Silent[0].Scopes.ToArray());
        Assert.AreNotEqual(Guid.Empty, scene.Silent[0].CorrelationId);
        Assert.AreEqual(ObservedCorrelation, outcome.Success.CorrelationId);
        Assert.AreEqual(scene.Silent[0].CorrelationId, outcome.Success.OperationId);
        Assert.AreEqual(Email, outcome.Success.Email);
        Assert.AreEqual(Guid.Parse(Tenant), outcome.Success.Tenant);
        Assert.AreEqual(0, scene.Interactive.Count);
        Assert.AreEqual(0, scene.Opened);
        Assert.IsTrue(scene.Tokens.All(token => token == scene.Original.Token));
        Assert.IsTrue(scene.Events.IndexOf("admitted") < scene.Events.IndexOf("loader"));
        Assert.IsTrue(scene.Events.IndexOf("loader") < scene.Events.IndexOf("session"));
    }

    [TestMethod]
    public async Task SilentClaimsContinueWithTheSameAccountAndNoCompetingHint()
    {
        using var scene = new Scene();
        const string claims = "{\"access_token\":{\"synthetic_claim\":null}}";
        scene.SilentFailure = Challenge(claims);
        var outcome = await scene.RunAsync();
        Assert.IsNotNull(outcome.Success, "A permitted silent challenge must reach one successful continuation.");
        Assert.IsTrue(outcome.Interactive);
        Assert.AreEqual(1, scene.Silent.Count);
        Assert.AreEqual(1, scene.Interactive.Count);
        var operation = scene.Interactive[0];
        Assert.AreSame(scene.Selected, operation.Account);
        Assert.IsNull(operation.LoginHint);
        Assert.AreEqual(claims, operation.Claims);
        Assert.AreEqual(Tenant, operation.Tenant);
        Assert.AreEqual((nint)42, operation.ParentWindow);
        CollectionAssert.AreEqual(new[] { Scope }, operation.Scopes.ToArray());
        Assert.AreEqual(operation.CorrelationId, outcome.Success.OperationId);
        Assert.AreNotEqual(scene.Silent[0].CorrelationId, operation.CorrelationId);
        Assert.AreEqual(1, scene.Opened);
        Assert.AreEqual(1, scene.Closed);
        Assert.IsTrue(scene.Tokens.All(token => token == scene.Original.Token));
    }

    [TestMethod]
    public async Task NoVisibleMatchUsesOnlyTheRequestedLoginHint()
    {
        using var scene = new Scene { IncludeSelectedAccount = false };
        var outcome = await scene.RunAsync();
        Assert.IsNotNull(outcome.Success, "No match with permission must use the requested login hint.");
        Assert.AreEqual(0, scene.Silent.Count);
        Assert.AreEqual(1, scene.Interactive.Count);
        Assert.IsNull(scene.Interactive[0].Account);
        Assert.AreEqual(Email, scene.Interactive[0].LoginHint);
        Assert.IsNull(scene.Interactive[0].Claims);
        Assert.AreEqual(Tenant, scene.Interactive[0].Tenant);
        Assert.AreEqual(1, scene.Closed);
    }

    [TestMethod]
    public async Task ASecondChallengeStopsAndDoesNotExposeProviderDetails()
    {
        using var scene = new Scene
        {
            SilentFailure = Challenge("{\"synthetic\":true}"),
            InteractiveFailure = Challenge("{\"second\":true}"),
        };
        Failure(AuthenticationFailure.InteractionRequired, await scene.RunAsync());
        Assert.AreEqual(1, scene.Silent.Count);
        Assert.AreEqual(1, scene.Interactive.Count);
        Assert.AreEqual(1, scene.Closed);
    }

    [TestMethod]
    public async Task DiscoveryFailureUsesTheSameSafeProviderClassification()
    {
        using var scene = new Scene { DiscoveryFailure = new MsalClientException("network_not_available", PrivateMarker) };
        var outcome = await scene.RunAsync();
        Failure(AuthenticationFailure.TemporarilyUnavailable, outcome);
        Assert.AreEqual(AuthenticationReason.NetworkTransient, outcome.Reason);
        Assert.AreEqual(1, scene.Discoveries);
        Assert.AreEqual(0, scene.Silent.Count);
        Assert.AreEqual(0, scene.Opened);
    }

    [TestMethod]
    public async Task ProviderInitializationFailureUsesTheSameSafeClassification()
    {
        using var scene = new Scene { InitializationFailure = new MsalClientException("network_not_available", PrivateMarker) };
        Failure(AuthenticationFailure.TemporarilyUnavailable, await scene.RunAsync());
        Assert.AreEqual(1, scene.Initializations);
        Assert.AreEqual(0, scene.Discoveries);
    }

    [TestMethod]
    public async Task CancellationDuringLoaderSetupPreventsSessionConstruction()
    {
        using var scene = new Scene();
        scene.DuringLoader = () => scene.Original.Cancel();
        Failure(AuthenticationFailure.Cancelled, await scene.RunAsync());
        Assert.IsTrue(scene.Events.Contains("loader"), "The controlled loader boundary must be reached.");
        Assert.AreEqual(0, scene.Initializations);
        Assert.AreEqual(0, scene.Discoveries);
    }

    [TestMethod]
    public async Task FailedLoaderSetupPreventsSessionConstruction()
    {
        using var scene = new Scene();
        scene.DuringLoader = () => throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable);
        Failure(AuthenticationFailure.MechanismUnavailable, await scene.RunAsync());
        Assert.IsTrue(scene.Events.Contains("loader"), "Unavailability must come from the attempted loader restriction.");
        Assert.AreEqual(0, scene.Initializations);
        Assert.AreEqual(0, scene.Discoveries);
    }

    [TestMethod]
    public async Task CancellationDuringSessionConstructionPreventsDiscovery()
    {
        using var scene = new Scene();
        scene.DuringInitialization = () => scene.Original.Cancel();
        Failure(AuthenticationFailure.Cancelled, await scene.RunAsync());
        Assert.AreEqual(1, scene.Initializations);
        Assert.AreEqual(0, scene.Discoveries);
    }

    [TestMethod]
    public async Task OriginalCancellationWinsOverADiscoveryFailure()
    {
        using var scene = new Scene();
        scene.DuringDiscovery = () => scene.Original.Cancel();
        scene.DiscoveryFailure = new MsalClientException("access_denied", PrivateMarker);
        Failure(AuthenticationFailure.Cancelled, await scene.RunAsync());
        Assert.AreEqual(1, scene.Discoveries);
        Assert.AreEqual(0, scene.Silent.Count);
        Assert.AreEqual(0, scene.Opened);
    }

    private static MsalUiRequiredException Challenge(string claims)
    {
        var value = JsonNode.Parse(new MsalUiRequiredException("invalid_grant", PrivateMarker).ToJsonString())!;
        value["claims"] = claims;
        return (MsalUiRequiredException)MsalException.FromJsonString(value.ToJsonString());
    }

    private static void Failure(AuthenticationFailure expected, AuthenticationOutcome outcome)
    {
        Assert.AreEqual(expected, outcome.Failure);
        Assert.IsNull(outcome.Success);
        var result = ResultProjection.Serialize(outcome);
        Assert.AreEqual(1, result.ExitCode);
        var text = Encoding.UTF8.GetString(result.Utf8Json);
        Assert.IsFalse(text.Contains(PrivateMarker, StringComparison.Ordinal));
        Assert.IsFalse(text.Contains("accessToken", StringComparison.Ordinal));
    }

    private sealed class Scene : IMsalSessionFactory, IMsalSession, IMsalHttpClientFactory,
        IWindowsHostAdmission, IRequestHost, IDisposable
    {
        internal Scene(bool legacy = false, string tenantPolicy = "explicit", bool personalAccount = false)
        {
            Profile = new("Synthetic", Guid.Parse(legacy
                ? "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" : "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                tenantPolicy == "fixed" ? Guid.Parse(Tenant) : null,
                legacy ? "visual-studio-legacy-wam" : "windows-wam",
                legacy ? "Microsoft" : "Synthetic fixture owner", "Synthetic fixture");
            var selector = tenantPolicy == "explicit" ? Tenant : null;
            Assert.IsTrue(ProfileSyntax.TryResolveTenant(Profile, selector, out var exactTenant));
            Request = new(Email, [Scope], true, exactTenant);
            Selected = new("PERSONAL@example.test", personalAccount ? MsaTenant : Tenant);
        }

        internal ClientProfile Profile { get; }
        internal AuthenticationRequest Request { get; }
        internal SyntheticAccount Selected { get; }
        internal CancellationTokenSource Original { get; } = new();
        internal MsalClientSettings? Settings;
        internal IMsalHttpClientFactory? HttpFactory;
        internal bool IncludeSelectedAccount { get; init; } = true;
        internal Exception? InitializationFailure, DiscoveryFailure, SilentFailure, InteractiveFailure;
        internal Action? DuringLoader, DuringInitialization, DuringDiscovery;
        internal int Initializations, Discoveries, Opened, Closed;
        internal List<string> Events { get; } = [];
        internal List<CancellationToken> Tokens { get; } = [];
        internal List<MsalSilentOperation> Silent { get; } = [];
        internal List<MsalInteractiveOperation> Interactive { get; } = [];
        public TimeProvider Clock { get; } = new FixedClock();

        internal Task<AuthenticationOutcome> RunAsync()
        {
            var provider = new LocalWindowsProvider(this, token =>
                MsalAuthenticationProvider.Initialize(Profile, Request, this, this, RestrictLoader, token));
            return new RequestCoordinator(provider, this).AuthenticateAsync(Request, Original.Token);
        }

        public void Admit(CancellationToken token) { Events.Add("admitted"); Tokens.Add(token); }
        public void Recheck(CancellationToken token) { Events.Add("rechecked"); Tokens.Add(token); }
        private void RestrictLoader(CancellationToken token)
        {
            Events.Add("loader"); Tokens.Add(token); DuringLoader?.Invoke();
        }

        public IMsalSession Create(MsalClientSettings settings, IMsalHttpClientFactory http, CancellationToken token)
        {
            Initializations++; Events.Add("session"); Tokens.Add(token);
            Settings = settings; HttpFactory = http;
            DuringInitialization?.Invoke();
            if (InitializationFailure is { } failure) throw failure;
            return this;
        }

        public Task<IReadOnlyList<IAccount>> GetAccountsAsync(CancellationToken token)
        {
            Discoveries++; Tokens.Add(token); DuringDiscovery?.Invoke();
            if (DiscoveryFailure is { } failure) return Task.FromException<IReadOnlyList<IAccount>>(failure);
            IReadOnlyList<IAccount> accounts = IncludeSelectedAccount
                ? [new SyntheticAccount("other@example.test", Tenant), Selected]
                : [new SyntheticAccount("other@example.test", Tenant)];
            return Task.FromResult(accounts);
        }

        public Task<AuthenticationResult> AcquireSilentAsync(MsalSilentOperation operation, CancellationToken token)
        {
            Silent.Add(operation); Tokens.Add(token);
            return SilentFailure is { } failure ? Task.FromException<AuthenticationResult>(failure)
                : Task.FromResult(Result());
        }

        public Task<AuthenticationResult> AcquireInteractiveAsync(MsalInteractiveOperation operation, CancellationToken token)
        {
            Interactive.Add(operation); Tokens.Add(token);
            return InteractiveFailure is { } failure ? Task.FromException<AuthenticationResult>(failure)
                : Task.FromResult(Result());
        }

        public HttpClient GetHttpClient() => throw new InvalidOperationException("Synthetic MSAL sessions do not use HTTP.");
        public Task<nint> OpenInteractionAsync(CancellationToken token)
        {
            Opened++; Tokens.Add(token); return Task.FromResult<nint>(42);
        }
        public Task CloseInteractionAsync() { Closed++; return Task.CompletedTask; }
        public void Dispose() => Original.Dispose();
        private AuthenticationResult Result() => new("synthetic-access", false, PrivateMarker,
            Now.AddHours(1), Now.AddHours(1), Tenant, new SyntheticAccount(Email, Tenant), PrivateMarker,
            [Scope], ObservedCorrelation, tokenType: "Bearer");
    }

    private sealed class SyntheticAccount(string username, string homeTenant) : IAccount
    {
        public string Username => username;
        public string Environment => "login.microsoftonline.com";
        public AccountId HomeAccountId { get; } = new(
            "55555555-6666-7777-8888-999999999999." + homeTenant,
            "55555555-6666-7777-8888-999999999999", homeTenant);
    }

    private sealed class FixedClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
