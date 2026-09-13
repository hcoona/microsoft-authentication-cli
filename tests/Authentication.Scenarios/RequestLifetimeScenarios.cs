using Authentication.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Scenarios;

// Controlled application scenarios, plus focused result-commitment rules. The harness
// timeout only detects a stuck test; it is not evidence of the Windows shutdown bound.
[TestClass]
public sealed class RequestLifetimeScenarios
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan HarnessLimit = TimeSpan.FromSeconds(2);

    [TestMethod]
    public async Task AlreadyCancelledRequestDoesNotDiscoverAccountsOrCreateUi()
    {
        using var caller = new CancellationTokenSource();
        caller.Cancel();
        var scene = new Scene();
        using var lifetime = new RequestLifetime(scene.Clock, scene.Clock.GetTimestamp(), Budget, caller.Token);
        var outcome = await scene.RunAsync(lifetime);

        AssertFailure(AuthenticationFailure.Cancelled, outcome);
        Assert.AreEqual(0, scene.Effects.Count);
    }

    [TestMethod]
    public async Task ExpiredEntryBudgetPreventsDiscoveryEvenWhenLifetimeIsCreatedLater()
    {
        var scene = new Scene();
        var entry = scene.Clock.GetTimestamp();
        scene.Clock.Advance(Budget);
        using var lifetime = new RequestLifetime(scene.Clock, entry, Budget);
        var outcome = await scene.RunAsync(lifetime);

        AssertFailure(AuthenticationFailure.Timeout, outcome);
        Assert.AreEqual(0, scene.Effects.Count);
    }

    [TestMethod]
    [DataRow("discover", false)]
    [DataRow("silent", false)]
    [DataRow("open", false)]
    [DataRow("interactive", false)]
    [DataRow("discover", true)]
    [DataRow("silent", true)]
    [DataRow("open", true)]
    [DataRow("interactive", true)]
    public async Task CancellationOrDeadlineEndsTheRequestWhileDependencyRemainsPending(string phase, bool deadline)
    {
        using var caller = new CancellationTokenSource();
        var scene = new Scene { PendingPhase = phase };
        using var lifetime = new RequestLifetime(scene.Clock, scene.Clock.GetTimestamp(), Budget, caller.Token);
        var run = scene.RunAsync(lifetime);
        try
        {
            await scene.Entered.Task.WaitAsync(HarnessLimit);
            Assert.IsFalse(run.IsCompleted);
            if (deadline) scene.Clock.Advance(Budget);
            else caller.Cancel();

            var outcome = await RequireOutcomeAsync(run);
            AssertFailure(deadline ? AuthenticationFailure.Timeout : AuthenticationFailure.Cancelled, outcome);
            Assert.IsTrue(scene.ProviderToken.IsCancellationRequested);
            Assert.IsFalse(scene.Body.IsCompleted, "A terminal outcome must not wait for an uncooperative dependency.");
            Assert.IsTrue(lifetime.TryCommit(out var committed));
            AssertFailure(deadline ? AuthenticationFailure.Timeout : AuthenticationFailure.Cancelled, committed!);
        }
        finally
        {
            await scene.ReleaseAndDrainAsync(run);
        }

        Assert.IsFalse(lifetime.TryCommit(out var duplicate));
        Assert.IsNull(duplicate);
        Assert.IsFalse(scene.Effects.SkipWhile(effect => effect != phase).Skip(1)
            .Any(effect => effect is "silent" or "open" or "interactive"));
    }

    [TestMethod]
    public async Task AdmissionAndProviderTimeShareTheOriginalDeadline()
    {
        var scene = new Scene { PendingPhase = "silent" };
        var entry = scene.Clock.GetTimestamp();
        scene.Clock.Advance(TimeSpan.FromSeconds(60));
        using var lifetime = new RequestLifetime(scene.Clock, entry, Budget);
        var run = scene.RunAsync(lifetime);
        try
        {
            await scene.Entered.Task.WaitAsync(HarnessLimit);
            scene.Clock.Advance(TimeSpan.FromSeconds(59));
            Assert.IsFalse(run.IsCompleted);
            scene.Clock.Advance(TimeSpan.FromSeconds(1));
            AssertFailure(AuthenticationFailure.Timeout, await RequireOutcomeAsync(run));
        }
        finally
        {
            await scene.ReleaseAndDrainAsync(run);
        }
    }

    [TestMethod]
    public async Task DelayedTimerCannotAcceptAResultValidatedAfterTheDeadline()
    {
        var scene = new Scene { PendingPhase = "silent" };
        using var lifetime = new RequestLifetime(scene.Clock, scene.Clock.GetTimestamp(), Budget);
        var run = scene.RunAsync(lifetime);
        try
        {
            await scene.Entered.Task.WaitAsync(HarnessLimit);
            scene.Clock.Advance(Budget, dispatchTimers: false);
            scene.Release.TrySetResult();
            AssertFailure(AuthenticationFailure.Timeout, await RequireOutcomeAsync(run));
        }
        finally
        {
            await scene.ReleaseAndDrainAsync(run);
        }
    }

    [TestMethod]
    [DataRow(-24)]
    [DataRow(24)]
    public async Task WallClockChangesDoNotConsumeOrRenewTheMonotonicBudget(int hours)
    {
        var scene = new Scene { PendingPhase = "silent" };
        using var lifetime = new RequestLifetime(scene.Clock, scene.Clock.GetTimestamp(), Budget);
        var run = scene.RunAsync(lifetime);
        try
        {
            await scene.Entered.Task.WaitAsync(HarnessLimit);
            scene.Clock.ShiftUtc(TimeSpan.FromHours(hours));
            scene.Clock.Advance(TimeSpan.FromSeconds(119));
            Assert.IsFalse(run.IsCompleted);
            scene.Release.TrySetResult();
            Assert.IsNotNull((await RequireOutcomeAsync(run)).Success);
        }
        finally
        {
            await scene.ReleaseAndDrainAsync(run);
        }
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task LateSuccessOrFailureCannotReplaceCancellation(bool lateFailure)
    {
        using var caller = new CancellationTokenSource();
        var scene = new Scene();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = new TaskCompletionSource<AuthenticationOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        var lateOutcome = lateFailure ? new AuthenticationOutcome(null, AuthenticationFailure.Denied) : scene.Success();
        using var lifetime = new RequestLifetime(scene.Clock, scene.Clock.GetTimestamp(), Budget, caller.Token);
        var run = lifetime.RunAsync(_ =>
        {
            entered.TrySetResult();
            return pending.Task;
        });
        try
        {
            await entered.Task.WaitAsync(HarnessLimit);
            caller.Cancel();
            AssertFailure(AuthenticationFailure.Cancelled, await RequireOutcomeAsync(run));
        }
        finally
        {
            pending.TrySetResult(lateOutcome);
            await lifetime.OperationCompletion.WaitAsync(HarnessLimit);
            await run.WaitAsync(HarnessLimit);
        }

        Assert.IsTrue(lifetime.TryCommit(out var committed));
        AssertFailure(AuthenticationFailure.Cancelled, committed!);
        Assert.IsFalse(committed!.PersistenceUnconfirmed);
    }

    [TestMethod]
    public async Task CallerCancellationBeforeCommitSuppressesValidatedSuccessAndWarning()
    {
        using var caller = new CancellationTokenSource();
        var scene = new Scene();
        using var lifetime = new RequestLifetime(scene.Clock, scene.Clock.GetTimestamp(), Budget, caller.Token);
        Assert.IsNotNull((await scene.RunAsync(lifetime)).Success);
        caller.Cancel();

        Assert.IsTrue(lifetime.TryCommit(out var committed));
        AssertFailure(AuthenticationFailure.Cancelled, committed!);
        Assert.IsFalse(committed!.PersistenceUnconfirmed);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task OnlyOneResultCanCommitAndLaterEventsCannotRewriteIt(bool failure)
    {
        using var caller = new CancellationTokenSource();
        var scene = new Scene();
        using var lifetime = new RequestLifetime(scene.Clock, scene.Clock.GetTimestamp(), Budget, caller.Token);
        Assert.IsFalse(lifetime.TryCommit(out var premature));
        Assert.IsNull(premature);
        var observed = await lifetime.RunAsync(_ => Task.FromResult(failure
            ? new AuthenticationOutcome(null, AuthenticationFailure.Denied) : scene.Success()));

        Assert.IsTrue(lifetime.TryCommit(out var committed));
        Assert.AreSame(observed, committed);
        caller.Cancel();
        scene.Clock.Advance(Budget);
        Assert.IsFalse(lifetime.TryCommit(out var duplicate));
        Assert.IsNull(duplicate);
        Assert.AreSame(observed, committed);
    }

    [TestMethod]
    public async Task CallerCancellationDoesNotReplaceAnAlreadyLatchedFailure()
    {
        using var caller = new CancellationTokenSource();
        var clock = new ScenarioClock();
        using var lifetime = new RequestLifetime(clock, clock.GetTimestamp(), Budget, caller.Token);
        await lifetime.RunAsync(_ => Task.FromResult(new AuthenticationOutcome(null, AuthenticationFailure.Denied)));
        caller.Cancel();

        Assert.IsTrue(lifetime.TryCommit(out var committed));
        AssertFailure(AuthenticationFailure.Denied, committed!);
    }

    [TestMethod]
    [DataRow("success")]
    [DataRow("denied")]
    [DataRow("invalid")]
    public async Task EveryTerminalOutcomeNotifiesTheRequestToken(string kind)
    {
        var scene = new Scene();
        using var lifetime = new RequestLifetime(scene.Clock, scene.Clock.GetTimestamp(), Budget);
        var supplied = CancellationToken.None;
        var expected = kind switch
        {
            "denied" => new(null, AuthenticationFailure.Denied),
            "invalid" => new(null, AuthenticationFailure.InvalidRequest),
            _ => scene.Success(),
        };
        var actual = await lifetime.RunAsync(token =>
        {
            supplied = token;
            return Task.FromResult(expected);
        });

        Assert.AreSame(expected, actual);
        Assert.IsTrue(supplied.IsCancellationRequested);
    }

    [TestMethod]
    public async Task UnexpectedAdmissionFailureBecomesSafeInternalFailure()
    {
        var clock = new ScenarioClock();
        using var lifetime = new RequestLifetime(clock, clock.GetTimestamp(), Budget);
        AuthenticationOutcome outcome;
        try
        {
            outcome = await lifetime.RunAsync(_ => throw new InvalidOperationException("synthetic-private-marker"));
        }
        catch (Exception)
        {
            Assert.Fail("Unexpected admission exceptions must become a safe terminal outcome.");
            throw;
        }

        AssertFailure(AuthenticationFailure.InternalFailure, outcome);
        Assert.IsFalse(outcome.ToString().Contains("synthetic-private-marker", StringComparison.Ordinal));
    }

    private static void AssertFailure(AuthenticationFailure expected, AuthenticationOutcome outcome)
    {
        Assert.AreEqual(expected, outcome.Failure);
        Assert.IsNull(outcome.Success);
    }

    private static async Task<AuthenticationOutcome> RequireOutcomeAsync(Task<AuthenticationOutcome> run)
    {
        try
        {
            return await run.WaitAsync(HarnessLimit);
        }
        catch (TimeoutException)
        {
            Assert.Fail("The request did not select its terminal outcome while the controlled dependency remained pending.");
            throw;
        }
    }

    private sealed class Scene : IAuthenticationProvider, IRequestHost
    {
        private const string Email = "personal@example.test";
        private const string Scope = "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation";
        private static readonly Guid Tenant = new("11111111-2222-3333-4444-555555555555");
        public string? PendingPhase { get; init; }
        public ScenarioClock Clock { get; } = new();
        TimeProvider IRequestHost.Clock => Clock;
        public List<string> Effects { get; } = [];
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<AuthenticationOutcome> Body { get; private set; } = Task.FromResult(new AuthenticationOutcome(null, AuthenticationFailure.InternalFailure));
        public CancellationToken ProviderToken { get; private set; }

        public Task<AuthenticationOutcome> RunAsync(RequestLifetime lifetime) => lifetime.RunAsync(token =>
            Body = new RequestCoordinator(this, this).AuthenticateAsync(new(Email, [Scope], true, Tenant), token));

        public async Task ReleaseAndDrainAsync(Task<AuthenticationOutcome> run)
        {
            Release.TrySetResult();
            await Body.WaitAsync(HarnessLimit);
            await run.WaitAsync(HarnessLimit);
        }

        public AuthenticationOutcome Success() => new(Candidate(Guid.NewGuid()), null, PersistenceUnconfirmed: true);

        public async Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken cancellationToken)
        {
            await PauseAsync("discover", cancellationToken);
            return PendingPhase is "open" or "interactive" ? [] : [new(Email, new object())];
        }

        public async Task<TokenCandidate> AcquireSilentAsync(AuthenticationRequest request, ProviderAccount account,
            Guid operationId, CancellationToken cancellationToken)
        {
            await PauseAsync("silent", cancellationToken);
            return Candidate(operationId);
        }

        public async Task<nint> OpenInteractionAsync(CancellationToken cancellationToken)
        {
            await PauseAsync("open", cancellationToken);
            return 42;
        }

        public async Task<TokenCandidate> AcquireInteractiveAsync(AuthenticationRequest request, ProviderAccount? account,
            string? claims, nint parentWindow, Guid operationId, CancellationToken cancellationToken)
        {
            await PauseAsync("interactive", cancellationToken);
            return Candidate(operationId);
        }

        public Task CloseInteractionAsync()
        {
            Effects.Add("close");
            return Task.CompletedTask;
        }

        private async Task PauseAsync(string phase, CancellationToken token)
        {
            Effects.Add(phase);
            ProviderToken = token;
            if (phase != PendingPhase) return;
            Entered.TrySetResult();
            await Release.Task;
        }

        private TokenCandidate Candidate(Guid operationId) => new("synthetic-token", Email, Tenant, [Scope],
            "Bearer", Clock.GetUtcNow().AddHours(1), operationId);
    }

    private sealed class ScenarioClock : TimeProvider
    {
        private readonly object gate = new();
        private readonly List<ManualTimer> timers = [];
        private long timestamp;
        private DateTimeOffset utc = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() { lock (gate) return timestamp; }
        public override DateTimeOffset GetUtcNow() { lock (gate) return utc; }
        public void ShiftUtc(TimeSpan delta) { lock (gate) utc += delta; }

        public void Advance(TimeSpan delta, bool dispatchTimers = true)
        {
            List<ManualTimer> due;
            lock (gate)
            {
                timestamp += delta.Ticks;
                utc += delta;
                due = dispatchTimers ? timers.Where(timer => timer.TakeDue(timestamp)).ToList() : [];
            }

            foreach (var timer in due) timer.Fire();
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            lock (gate)
            {
                var timer = new ManualTimer(this, callback, state);
                timers.Add(timer);
                timer.Change(dueTime, period);
                return timer;
            }
        }

        private sealed class ManualTimer(ScenarioClock clock, TimerCallback callback, object? state) : ITimer
        {
            private long? due;
            private bool disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                if (period != System.Threading.Timeout.InfiniteTimeSpan) throw new NotSupportedException("One-shot fixture timers only.");
                lock (clock.gate)
                {
                    if (disposed) return false;
                    due = dueTime == System.Threading.Timeout.InfiniteTimeSpan ? null : clock.timestamp + dueTime.Ticks;
                    return true;
                }
            }

            public bool TakeDue(long now)
            {
                if (disposed || due is null || due > now) return false;
                due = null;
                return true;
            }

            public void Fire() => callback(state);
            public void Dispose() { lock (clock.gate) { disposed = true; due = null; } }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
