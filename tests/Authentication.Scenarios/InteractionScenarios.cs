using Authentication.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Scenarios;

// Exercise caller-visible outcomes and required provider/UI effects at the application
// boundary. The host and provider are synthetic; no window or account store is used.
[TestClass]
public sealed class InteractionScenarios
{
    private const string Email = "personal@example.test";
    private const string WorkEmail = "work@example.test";
    private const string Scope = "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation";
    private static readonly Guid Tenant = new("11111111-2222-3333-4444-555555555555");
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public async Task PermissionDoesNotCreateUiWhenSelectedAccountSilentReuseSucceeds()
    {
        var scene = new Scene();
        var outcome = await scene.RunAsync();

        Assert.IsNotNull(outcome.Success);
        Assert.IsNull(outcome.Failure);
        Assert.IsFalse(outcome.Interactive);
        CollectionAssert.AreEqual(new[] { "discover", "silent" }, scene.Effects.ToArray());
    }

    [TestMethod]
    public async Task MissingSelectedAccountUsesOnePermittedInteractiveCallWithoutSubstitutingWorkAccount()
    {
        var scene = new Scene { Accounts = [new(WorkEmail, new object())] };
        var outcome = await scene.RunAsync();

        Assert.IsNotNull(outcome.Success);
        Assert.AreEqual(Email, outcome.Success.Email);
        Assert.IsTrue(outcome.Interactive);
        Assert.IsTrue(outcome.PersistenceUnconfirmed);
        Assert.IsNull(scene.InteractiveAccount);
        Assert.IsNull(scene.InteractiveClaims);
        Assert.AreEqual(Email, scene.InteractiveEmail);
        Assert.AreEqual(scene.ParentWindow, scene.InteractiveParent);
        CollectionAssert.AreEqual(new[] { "discover", "open", "interactive", "close" }, scene.Effects.ToArray());
    }

    [TestMethod]
    public async Task SilentInteractionRequirementPreservesSelectedAccountAndRequestLocalClaims()
    {
        var scene = new Scene
        {
            SilentFailure = new ProviderFailureException(AuthenticationFailure.InteractionRequired, "synthetic-claims"),
        };
        var outcome = await scene.RunAsync();

        Assert.IsNotNull(outcome.Success);
        Assert.IsTrue(outcome.Interactive);
        Assert.AreSame(scene.Accounts[0], scene.InteractiveAccount);
        Assert.AreEqual("synthetic-claims", scene.InteractiveClaims);
        Assert.AreEqual(Email, scene.InteractiveEmail);
        CollectionAssert.AreEqual(new[] { "discover", "silent", "open", "interactive", "close" }, scene.Effects.ToArray());
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ProhibitedInteractionNeverCreatesUiOrAcquiresInteractively(bool accountVisible)
    {
        var scene = new Scene
        {
            Accounts = accountVisible ? [new(Email, new object())] : [],
            SilentFailure = new ProviderFailureException(AuthenticationFailure.InteractionRequired),
        };
        var outcome = await scene.RunAsync(interactionAllowed: false);

        Assert.AreEqual(AuthenticationFailure.InteractionRequired, outcome.Failure);
        Assert.IsNull(outcome.Success);
        CollectionAssert.AreEqual(accountVisible ? new[] { "discover", "silent" } : ["discover"], scene.Effects.ToArray());
    }

    [TestMethod]
    public async Task PermissionCannotResolveAmbiguityByOpeningAnAccountPicker()
    {
        var scene = new Scene { Accounts = [new(Email, new object()), new(Email.ToUpperInvariant(), new object())] };
        var outcome = await scene.RunAsync();

        Assert.AreEqual(AuthenticationFailure.AccountAmbiguous, outcome.Failure);
        Assert.IsNull(outcome.Success);
        CollectionAssert.AreEqual(new[] { "discover" }, scene.Effects.ToArray());
    }

    [TestMethod]
    public async Task ParentCreationFailurePreventsTheInteractiveCall()
    {
        var scene = new Scene { Accounts = [], ParentWindow = 0 };
        var outcome = await scene.RunAsync();

        Assert.AreEqual(AuthenticationFailure.MechanismUnavailable, outcome.Failure);
        Assert.IsNull(outcome.Success);
        Assert.IsFalse(scene.Effects.Contains("interactive"));
    }

    [TestMethod]
    public async Task InteractiveAcquisitionWaitsForTheOwnedParentToBecomeReady()
    {
        var readiness = new TaskCompletionSource<nint>(TaskCreationOptions.RunContinuationsAsynchronously);
        var scene = new Scene { Accounts = [], ParentReadiness = readiness.Task };
        var operation = scene.RunAsync();

        try
        {
            Assert.IsFalse(operation.IsCompleted, "Authentication must await its owned parent.");
            Assert.IsFalse(scene.Effects.Contains("interactive"));
        }
        finally
        {
            readiness.SetResult(scene.ParentWindow);
        }

        var outcome = await operation;
        Assert.IsNotNull(outcome.Success);
        Assert.AreEqual(scene.ParentWindow, scene.InteractiveParent);
        CollectionAssert.AreEqual(new[] { "discover", "open", "interactive", "close" }, scene.Effects.ToArray());
    }

    [TestMethod]
    [DataRow(AuthenticationFailure.Cancelled)]
    [DataRow(AuthenticationFailure.Denied)]
    [DataRow(AuthenticationFailure.MechanismUnavailable)]
    [DataRow(AuthenticationFailure.TemporarilyUnavailable)]
    [DataRow(AuthenticationFailure.InternalFailure)]
    public async Task TerminalSilentFailuresDoNotOpenUiOrRetry(AuthenticationFailure failure)
    {
        var scene = new Scene { SilentFailure = new ProviderFailureException(failure) };
        var outcome = await scene.RunAsync();

        Assert.AreEqual(failure, outcome.Failure);
        Assert.IsNull(outcome.Success);
        CollectionAssert.AreEqual(new[] { "discover", "silent" }, scene.Effects.ToArray());
    }

    [TestMethod]
    [DataRow(AuthenticationFailure.InteractionRequired)]
    [DataRow(AuthenticationFailure.Cancelled)]
    [DataRow(AuthenticationFailure.Denied)]
    [DataRow(AuthenticationFailure.MechanismUnavailable)]
    [DataRow(AuthenticationFailure.TemporarilyUnavailable)]
    [DataRow(AuthenticationFailure.InternalFailure)]
    public async Task InteractiveFailureClosesOwnedUiWithoutAnotherAttempt(AuthenticationFailure failure)
    {
        var scene = new Scene { Accounts = [], InteractiveFailure = new ProviderFailureException(failure, "synthetic-claims") };
        var outcome = await scene.RunAsync();

        Assert.AreEqual(failure, outcome.Failure);
        Assert.IsNull(outcome.Success);
        CollectionAssert.AreEqual(new[] { "discover", "open", "interactive", "close" }, scene.Effects.ToArray());
    }

    [TestMethod]
    [DataRow("wrong-email")]
    [DataRow("wrong-tenant")]
    [DataRow("wrong-operation")]
    public async Task InteractiveSuccessStillMustSatisfyTheOriginalRequest(string defect)
    {
        var scene = new Scene { Accounts = [], InteractiveDefect = defect };
        var outcome = await scene.RunAsync();

        Assert.AreEqual(AuthenticationFailure.IdentityValidationFailed, outcome.Failure);
        Assert.IsNull(outcome.Success);
        CollectionAssert.AreEqual(new[] { "discover", "open", "interactive", "close" }, scene.Effects.ToArray());
    }

    [TestMethod]
    [DataRow("discover")]
    [DataRow("silent")]
    [DataRow("interactive")]
    public async Task UnrecognizedProviderFailureBecomesSafeInternalFailure(string phase)
    {
        var scene = new Scene
        {
            Accounts = phase == "interactive" ? [] : [new(Email, new object())],
            UnexpectedFailurePhase = phase,
        };
        var outcome = await scene.RunAsync();

        Assert.AreEqual(AuthenticationFailure.InternalFailure, outcome.Failure);
        Assert.IsNull(outcome.Success);
        Assert.IsFalse(outcome.ToString().Contains("synthetic-private-marker", StringComparison.Ordinal));
        if (phase == "interactive") Assert.AreEqual("close", scene.Effects[^1]);
    }

    private sealed class Scene : IAuthenticationProvider, IRequestHost
    {
        public IReadOnlyList<ProviderAccount> Accounts { get; init; } = [new(Email, new object())];
        public Exception? SilentFailure { get; init; }
        public Exception? InteractiveFailure { get; init; }
        public string? UnexpectedFailurePhase { get; init; }
        public string? InteractiveDefect { get; init; }
        public nint ParentWindow { get; init; } = 42;
        public Task<nint>? ParentReadiness { get; init; }
        public List<string> Effects { get; } = [];
        public ProviderAccount? InteractiveAccount { get; private set; }
        public string? InteractiveEmail { get; private set; }
        public string? InteractiveClaims { get; private set; }
        public nint InteractiveParent { get; private set; }
        public TimeProvider Clock { get; } = new ScenarioClock();

        public async Task<AuthenticationOutcome> RunAsync(bool interactionAllowed = true)
        {
            try
            {
                return await new RequestCoordinator(this, this).AuthenticateAsync(new(Email, [Scope], interactionAllowed, Tenant));
            }
            catch (Exception)
            {
                Assert.Fail("Provider failures must become an authentication outcome without escaping the application boundary.");
                throw;
            }
        }

        public Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken cancellationToken)
        {
            Effects.Add("discover");
            FailIfRequested("discover");
            return Task.FromResult(Accounts);
        }

        public Task<TokenCandidate> AcquireSilentAsync(AuthenticationRequest request, ProviderAccount account,
            Guid operationId, CancellationToken cancellationToken)
        {
            Effects.Add("silent");
            FailIfRequested("silent");
            if (SilentFailure is not null) throw SilentFailure;
            return Task.FromResult(Candidate(operationId));
        }

        public Task<TokenCandidate> AcquireInteractiveAsync(AuthenticationRequest request, ProviderAccount? account,
            string? claims, nint parentWindow, Guid operationId, CancellationToken cancellationToken)
        {
            Effects.Add("interactive");
            InteractiveParent = parentWindow;
            InteractiveAccount = account;
            InteractiveEmail = request.AccountEmail;
            InteractiveClaims = claims;
            FailIfRequested("interactive");
            if (InteractiveFailure is not null) throw InteractiveFailure;
            var candidate = Candidate(operationId);
            return Task.FromResult(InteractiveDefect switch
            {
                "wrong-email" => candidate with { Email = WorkEmail },
                "wrong-tenant" => candidate with { Tenant = Guid.Empty },
                "wrong-operation" => candidate with { OperationId = Guid.Empty },
                _ => candidate,
            });
        }

        public Task<nint> OpenInteractionAsync(CancellationToken cancellationToken)
        {
            Effects.Add("open");
            return ParentReadiness ?? Task.FromResult(ParentWindow);
        }

        public Task CloseInteractionAsync()
        {
            Effects.Add("close");
            return Task.CompletedTask;
        }

        private void FailIfRequested(string phase)
        {
            if (UnexpectedFailurePhase == phase) throw new InvalidOperationException("synthetic-private-marker");
        }

        private static TokenCandidate Candidate(Guid operationId) =>
            new("synthetic-interactive-access", Email, Tenant, [Scope], "Bearer", Now.AddMinutes(5), operationId);
    }

    private sealed class ScenarioClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
