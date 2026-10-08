using System.Diagnostics;

namespace Authentication.Core;

public enum AuthenticationStage
{
    ProfileRead, AccountDiscovery, SilentAcquisition, InteractionOpen,
    InteractiveAcquisition, CandidateValidation, InteractionClose,
}

// Standard OTel instrumentation without making observation ambient to providers.
public sealed class AuthenticationTrace : IDisposable
{
    public const string SourceName = "hcoona.microsoft-authentication-cli";
    private static readonly Lazy<ActivitySource?> Source = new(() =>
    {
        try { return new(SourceName, "0.0.0"); }
        catch (Exception) { return null; }
    });
    private Activity? request;

    private AuthenticationTrace() => request = StartActivity("request", default);

    public static AuthenticationTrace Start() => new();

    internal static bool Owns(ActivitySource source) => ReferenceEquals(source, Source.Value);
    internal static void InitializeSource() => _ = Source.Value;

    internal static string? StageName(AuthenticationStage stage) => stage switch
    {
        AuthenticationStage.ProfileRead => "profile_read",
        AuthenticationStage.AccountDiscovery => "account_discovery",
        AuthenticationStage.SilentAcquisition => "silent_acquisition",
        AuthenticationStage.InteractionOpen => "interaction_open",
        AuthenticationStage.InteractiveAcquisition => "interactive_acquisition",
        AuthenticationStage.CandidateValidation => "candidate_validation",
        AuthenticationStage.InteractionClose => "interaction_close",
        _ => null,
    };

    internal static bool KnownStage(string name) => name is "request" or "profile_read"
        or "account_discovery" or "silent_acquisition" or "interaction_open"
        or "interactive_acquisition" or "candidate_validation" or "interaction_close";

    public IDisposable? Begin(AuthenticationStage stage)
    {
        var parent = Volatile.Read(ref request);
        var name = StageName(stage);
        if (parent is null || name is null) return null;
        var activity = StartActivity(name, parent.Context);
        return activity is null ? null : new Phase(activity);
    }

    internal void Committed(AuthenticationOutcome outcome)
    {
        try
        {
            // Setting status does not invoke listeners or perform export work.
            Volatile.Read(ref request)?.SetStatus(outcome.Success is not null && outcome.Failure is null
                ? ActivityStatusCode.Ok : ActivityStatusCode.Error);
        }
        catch (Exception) { }
    }

    private static Activity? StartActivity(string name, ActivityContext parent)
    {
        var previous = Activity.Current;
        try
        {
            var source = Source.Value;
            if (source?.HasListeners() != true) return null;
            Activity.Current = null;
            return source.StartActivity(name, ActivityKind.Internal, parent);
        }
        catch (Exception) { return null; }
        finally { Restore(previous); }
    }

    private static void Stop(Activity? activity)
    {
        if (activity is null) return;
        var previous = Activity.Current;
        try { activity.Stop(); }
        catch (Exception) { }
        finally { Restore(previous); }
    }

    private static void Restore(Activity? previous)
    {
        try { Activity.Current = previous; }
        catch (Exception) { }
    }

    public void Dispose() => Stop(Interlocked.Exchange(ref request, null));

    private sealed class Phase(Activity activity) : IDisposable
    {
        private Activity? current = activity;
        public void Dispose() => Stop(Interlocked.Exchange(ref current, null));
    }
}
