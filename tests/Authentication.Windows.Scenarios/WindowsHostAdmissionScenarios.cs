using System.Runtime.InteropServices;
using System.Text;
using Authentication.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Windows.Scenarios;

// Real admission/provider/coordinator boundaries consume synthetic local facts.
// No native query, Windows account metadata, window, MSAL application, file,
// network operation or child-product process is used by these scenarios.
[TestClass]
public sealed class WindowsHostAdmissionScenarios
{
    private const string Email = "personal@example.test";
    private const string Scope = "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation";
    private const string PrivateMarker = "SYNTHETIC-HOST-OBSERVATION-PRIVATE-MARKER";
    private static readonly Guid Tenant = new("11111111-2222-3333-4444-555555555555");
    private static readonly DateTimeOffset Now = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);
    private static readonly string[] AdmissionObservations =
        ["platform", "product", "thread", "logon", "session", "desktop"];

    [TestMethod]
    public void ConstructionDoesNotObserveLocalState()
    {
        using var scene = new Scene();
        _ = new WindowsHostAdmission(scene);
        Assert.AreEqual(0, scene.Observed.Count);
        NoProviderEffects(scene);
    }

    [TestMethod]
    public async Task PrecancelledRequestDoesNotObserveLocalState()
    {
        using var scene = new Scene();
        scene.Original.Cancel();
        Failure(AuthenticationFailure.Cancelled, await scene.RunAsync());
        Assert.AreEqual(0, scene.Observed.Count);
        NoProviderEffects(scene);
    }

    [TestMethod]
    public async Task OrdinaryInteractiveLogonKindsPermitSelectedAccountAcquisition()
    {
        foreach (var kind in new uint[] { 2, 10, 11, 12 })
        {
            using var scene = new Scene();
            scene.Logon = scene.Logon! with { LogonType = kind };
            if (kind != 2) scene.Platform = scene.Platform with { Version = new Version(10, 0, 26200) };
            var outcome = await scene.RunAsync();
            Assert.IsNotNull(outcome.Success, "An admitted ordinary-user host did not reach acquisition.");
            Assert.AreEqual(Email, outcome.Success.Email);
            Assert.AreEqual(1, scene.Initializations);
            Assert.AreEqual(1, scene.Discoveries);
            Assert.AreEqual(1, scene.SilentCalls);
            Assert.AreEqual(0, scene.Opened);
            Assert.IsTrue(scene.Tokens.All(token => token == scene.Original.Token));
        }
    }

    [TestMethod]
    public async Task UnsupportedPlatformStopsBeforeWindowsObservations()
    {
        var valid = ValidPlatform();
        foreach (var platform in new[]
        {
            valid with { IsWindows = false },
            valid with { ProcessArchitecture = Architecture.Arm64 },
            valid with { ProcessArchitecture = Architecture.X86 },
            valid with { OsArchitecture = Architecture.Arm64 },
            valid with { Version = new Version(10, 0, 21999) },
            valid with { Version = new Version(6, 3, 9600) },
            valid with { Version = new Version(10, 1, 22000) },
        })
        {
            using var scene = new Scene { Platform = platform };
            await RejectedAfter(scene, "platform");
            CollectionAssert.AreEqual(new[] { "platform" }, scene.Observed);
        }
    }

    [TestMethod]
    public async Task ServerOrUnobservableProductPreventsInitialization()
    {
        foreach (var product in new bool?[] { false, null })
        {
            using var scene = new Scene { Workstation = product };
            await RejectedAfter(scene, "product");
        }
    }

    [TestMethod]
    public async Task ImpersonationOrUnknownThreadIdentityPreventsInitialization()
    {
        foreach (var identity in new[] { WindowsThreadIdentity.Impersonating, WindowsThreadIdentity.Unavailable })
        {
            using var scene = new Scene { ThreadIdentity = identity };
            await RejectedAfter(scene, "thread");
        }
    }

    [TestMethod]
    public async Task MissingOrInvalidOwnLogonPreventsInitialization()
    {
        foreach (var logon in new WindowsLocalLogon?[]
        {
            null,
            new(2, WindowsLogonIdentity.Invalid, true, true),
        })
        {
            using var scene = new Scene { Logon = logon };
            await RejectedAfter(scene, "logon");
        }
    }

    [TestMethod]
    public async Task ServiceIdentitiesPrecludeAccountDiscovery()
    {
        foreach (var identity in new[]
        {
            WindowsLogonIdentity.LocalSystem, WindowsLogonIdentity.LocalService,
            WindowsLogonIdentity.NetworkService,
        })
        {
            using var scene = new Scene { Logon = new(2, identity, true, true) };
            await RejectedAfter(scene, "logon");
        }
    }

    [TestMethod]
    public async Task NoninteractiveAndAlternateCredentialLogonKindsAreRejected()
    {
        foreach (var kind in new uint[] { 0, 3, 4, 5, 8, 9, 13 })
        {
            using var scene = new Scene { Logon = new(kind, WindowsLogonIdentity.User, true, true) };
            await RejectedAfter(scene, "logon");
        }
    }

    [TestMethod]
    public async Task HiddenWindowStationPreventsInitialization()
    {
        using var scene = new Scene { Logon = new(2, WindowsLogonIdentity.User, false, true) };
        await RejectedAfter(scene, "logon");
    }

    [TestMethod]
    public async Task MissingOrDifferentWindowStationUserPreventsInitialization()
    {
        foreach (var matches in new bool?[] { false, null })
        {
            using var scene = new Scene { Logon = new(2, WindowsLogonIdentity.User, true, matches) };
            await RejectedAfter(scene, "logon");
        }
    }

    [TestMethod]
    public async Task InactiveOrUnobservableSessionPreventsInitialization()
    {
        foreach (var connection in new[]
        {
            WindowsSessionConnection.Inactive, WindowsSessionConnection.Unavailable,
            WindowsSessionConnection.ZeroSession, WindowsSessionConnection.Malformed,
        })
        {
            using var scene = new Scene { Session = connection };
            await RejectedAfter(scene, "session");
        }
    }

    [TestMethod]
    public async Task NoninputOrUnobservableDesktopPreventsInitialization()
    {
        foreach (var receivesInput in new bool?[] { false, null })
        {
            using var scene = new Scene { InputDesktop = receivesInput };
            await RejectedAfter(scene, "desktop");
        }
    }

    [TestMethod]
    public async Task CancellationAfterAnyObservationStopsFurtherQueriesAndInitialization()
    {
        foreach (var observation in AdmissionObservations)
        {
            using var scene = new Scene();
            scene.DuringObservation = name => { if (name == observation) scene.Original.Cancel(); };
            Failure(AuthenticationFailure.Cancelled, await scene.RunAsync());
            Assert.AreEqual(observation, scene.Observed.Last());
            NoProviderEffects(scene);
        }
    }

    [TestMethod]
    public async Task OriginalCancellationWinsWhenAnObservationThrows()
    {
        foreach (var observation in AdmissionObservations)
        {
            using var scene = new Scene();
            scene.DuringObservation = name =>
            {
                if (name != observation) return;
                scene.Original.Cancel();
                throw new InvalidOperationException(PrivateMarker);
            };
            Failure(AuthenticationFailure.Cancelled, await scene.RunAsync());
            Assert.AreEqual(observation, scene.Observed.Last());
            NoProviderEffects(scene);
        }
    }

    [TestMethod]
    public async Task UnexpectedObservationFaultRemainsSanitizedInternalFailure()
    {
        foreach (var observation in AdmissionObservations)
        {
            using var scene = new Scene();
            scene.DuringObservation = name =>
            {
                if (name == observation) throw new InvalidOperationException(PrivateMarker);
            };
            Failure(AuthenticationFailure.InternalFailure, await scene.RunAsync());
            NoProviderEffects(scene);
        }
    }

    [TestMethod]
    public async Task SessionLossBeforeSilentAcquisitionPreventsItsEffect()
    {
        using var scene = new Scene();
        scene.DuringObservation = _ =>
        {
            if (scene.Discoveries != 0) scene.Session = WindowsSessionConnection.Inactive;
        };
        Failure(AuthenticationFailure.MechanismUnavailable, await scene.RunAsync());
        Assert.AreEqual(1, scene.Discoveries, "Discovery was not reached before the volatile session change.");
        Assert.AreEqual(0, scene.SilentCalls);
        Assert.AreEqual(0, scene.Opened);
    }

    [TestMethod]
    public async Task ImpersonationBeforeSilentAcquisitionPreventsItsEffect()
    {
        using var scene = new Scene();
        scene.DuringObservation = _ =>
        {
            if (scene.Discoveries != 0) scene.ThreadIdentity = WindowsThreadIdentity.Impersonating;
        };
        Failure(AuthenticationFailure.MechanismUnavailable, await scene.RunAsync());
        Assert.AreEqual(1, scene.Discoveries, "Discovery was not reached before the volatile identity change.");
        Assert.AreEqual(0, scene.SilentCalls);
    }

    [TestMethod]
    public async Task InputDesktopLossAfterReadinessPreventsInteractionAndClosesParent()
    {
        using var scene = new Scene { RequiresInteraction = true };
        scene.DuringObservation = _ => { if (scene.Opened != 0) scene.InputDesktop = false; };
        Failure(AuthenticationFailure.MechanismUnavailable, await scene.RunAsync());
        Assert.AreEqual(1, scene.Opened, "The controlled parent was not reached before the desktop change.");
        Assert.AreEqual(1, scene.Closed);
        Assert.AreEqual(0, scene.InteractiveCalls);
    }

    [TestMethod]
    public async Task CancellationDuringVolatileObservationPreventsAcquisition()
    {
        using var scene = new Scene();
        scene.DuringObservation = name =>
        {
            if (scene.Discoveries != 0 && name == "thread") scene.Original.Cancel();
        };
        Failure(AuthenticationFailure.Cancelled, await scene.RunAsync());
        Assert.AreEqual(1, scene.Discoveries);
        Assert.AreEqual("thread", scene.Observed.Last());
        Assert.AreEqual(0, scene.SilentCalls);
    }

    [TestMethod]
    public async Task EachProviderEffectHasFreshVolatileObservations()
    {
        using var scene = new Scene { RequiresInteraction = true };
        var outcome = await scene.RunAsync();
        Assert.IsNotNull(outcome.Success, "The admitted interactive continuation was not completed.");
        Assert.AreEqual(1, scene.InteractiveCalls);
        Assert.AreEqual(1, scene.Closed);
        Assert.AreEqual(3, scene.ProviderObservationSets.Count);
        foreach (var observations in scene.ProviderObservationSets)
            foreach (var required in new[] { "thread", "session", "desktop" })
                CollectionAssert.Contains(observations, required);
    }

    [TestMethod]
    public async Task ObservationsRunOnTheCallingThreadWithOriginalCancellation()
    {
        using var scene = new Scene { RequiresInteraction = true };
        var thread = Environment.CurrentManagedThreadId;
        scene.DuringObservation = _ => Assert.AreEqual(thread, Environment.CurrentManagedThreadId);
        var outcome = await scene.RunAsync();
        Assert.IsNotNull(outcome.Success, "Calling-thread observations did not release the request.");
        Assert.IsTrue(scene.Tokens.All(token => token == scene.Original.Token));
        Assert.AreEqual(1, scene.InteractiveCalls);
    }

    private static WindowsHostPlatform ValidPlatform() => new(true, Architecture.X64, Architecture.X64, new(10, 0, 22000));

    private static async Task RejectedAfter(Scene scene, string observation)
    {
        Failure(AuthenticationFailure.MechanismUnavailable, await scene.RunAsync());
        Assert.IsTrue(scene.Observed.Contains(observation), $"The required {observation} observation was not reached.");
        Assert.AreEqual(observation, scene.Observed.Last());
        NoProviderEffects(scene);
        Assert.AreEqual(0, scene.Opened);
    }

    private static void Failure(AuthenticationFailure expected, AuthenticationOutcome outcome)
    {
        Assert.AreEqual(expected, outcome.Failure);
        Assert.IsNull(outcome.Success);
        var json = Encoding.UTF8.GetString(ResultProjection.Serialize(outcome).Utf8Json);
        Assert.IsFalse(json.Contains(PrivateMarker, StringComparison.Ordinal));
        Assert.IsFalse(json.Contains(Email, StringComparison.Ordinal));
    }

    private static void NoProviderEffects(Scene scene)
    {
        Assert.AreEqual(0, scene.Initializations);
        Assert.AreEqual(0, scene.Discoveries);
        Assert.AreEqual(0, scene.SilentCalls);
        Assert.AreEqual(0, scene.InteractiveCalls);
    }

    private sealed class Scene : IWindowsHostObservations, IAuthenticationProvider, IRequestHost, IDisposable
    {
        internal CancellationTokenSource Original { get; } = new();
        internal WindowsHostPlatform Platform { get; set; } = ValidPlatform();
        internal bool? Workstation { get; set; } = true;
        internal WindowsThreadIdentity ThreadIdentity { get; set; } = WindowsThreadIdentity.NoToken;
        internal WindowsLocalLogon? Logon { get; set; } = new(2, WindowsLogonIdentity.User, true, true);
        internal WindowsSessionConnection Session { get; set; } = WindowsSessionConnection.Active;
        internal bool? InputDesktop { get; set; } = true;
        internal bool RequiresInteraction { get; set; }
        internal Action<string>? DuringObservation { get; set; }
        internal List<string> Observed { get; } = [];
        internal List<CancellationToken> Tokens { get; } = [];
        internal List<string[]> ProviderObservationSets { get; } = [];
        private readonly List<string> observationsSinceEffect = [];
        internal int Initializations, Discoveries, SilentCalls, InteractiveCalls, Opened, Closed;
        public TimeProvider Clock { get; } = new FixedClock();

        internal Task<AuthenticationOutcome> RunAsync()
        {
            var provider = new LocalWindowsProvider(new WindowsHostAdmission(this), token =>
            {
                Initializations++;
                Tokens.Add(token);
                observationsSinceEffect.Clear();
                return this;
            });
            return new RequestCoordinator(provider, this).AuthenticateAsync(
                new(Email, [Scope], true, Tenant), Original.Token);
        }

        private void Observe(string name, CancellationToken cancellationToken)
        {
            Observed.Add(name);
            observationsSinceEffect.Add(name);
            Tokens.Add(cancellationToken);
            DuringObservation?.Invoke(name);
        }

        // Deliberately do not cooperate with cancellation: the production boundary
        // must notice it before classifying a result or beginning the next query.
        public WindowsHostPlatform ReadPlatform(CancellationToken token) { Observe("platform", token); return Platform; }
        public bool? ReadWorkstationProduct(CancellationToken token) { Observe("product", token); return Workstation; }
        public WindowsThreadIdentity ReadThreadIdentity(CancellationToken token) { Observe("thread", token); return ThreadIdentity; }
        public WindowsLocalLogon? ReadOwnLogonAndStation(CancellationToken token) { Observe("logon", token); return Logon; }
        public WindowsSessionConnection ReadSessionConnection(CancellationToken token) { Observe("session", token); return Session; }
        public bool? ReadInputDesktop(CancellationToken token) { Observe("desktop", token); return InputDesktop; }

        public Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken token)
        {
            BeginProviderEffect();
            Discoveries++;
            Tokens.Add(token);
            return Task.FromResult<IReadOnlyList<ProviderAccount>>([new(Email, new object())]);
        }

        public Task<TokenCandidate> AcquireSilentAsync(AuthenticationRequest request, ProviderAccount account,
            Guid operationId, CancellationToken token)
        {
            BeginProviderEffect();
            SilentCalls++;
            Tokens.Add(token);
            return RequiresInteraction
                ? Task.FromException<TokenCandidate>(new ProviderFailureException(AuthenticationFailure.InteractionRequired))
                : Task.FromResult(Candidate(request, operationId));
        }

        public Task<TokenCandidate> AcquireInteractiveAsync(AuthenticationRequest request, ProviderAccount? account,
            string? claims, nint parent, Guid operationId, CancellationToken token)
        {
            BeginProviderEffect();
            InteractiveCalls++;
            Tokens.Add(token);
            return Task.FromResult(Candidate(request, operationId));
        }

        public Task<nint> OpenInteractionAsync(CancellationToken token)
        {
            Opened++;
            Tokens.Add(token);
            return Task.FromResult<nint>(1); // Synthetic parent; never used by a native API.
        }

        public Task CloseInteractionAsync() { Closed++; return Task.CompletedTask; }
        public void Dispose() => Original.Dispose();
        private void BeginProviderEffect()
        {
            ProviderObservationSets.Add(observationsSinceEffect.ToArray());
            observationsSinceEffect.Clear();
        }
        private static TokenCandidate Candidate(AuthenticationRequest request, Guid operationId) =>
            new("synthetic-token", Email, Tenant, request.Scopes, "Bearer", Now.AddHours(1), operationId);
    }

    private sealed class FixedClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
