namespace Authentication.Core;

// The Windows implementation owns fixed-volume admission, one bounded file read,
// and cancellation. This seam supplies bytes without selecting or provisioning a Profile.
public interface IProfileSource
{
    Task<ReadOnlyMemory<byte>> ReadAsync(string path, CancellationToken cancellationToken);
}

// One managed authentication invocation. The process host captures entryTimestamp
// before parsing and retains this object through its bounded shutdown drain.
public sealed class RequestInvocation : IDisposable
{
    private readonly RequestLifetime lifetime;

    public ParsedRequest? Request { get; }

    public Task OperationCompletion => lifetime.OperationCompletion;

    public RequestInvocation(IReadOnlyList<string> arguments, IRequestHost host,
        long entryTimestamp, CancellationToken cancellationToken = default)
    {
        Request = RequestSyntax.Parse(arguments);
        lifetime = new(host.Clock, entryTimestamp,
            TimeSpan.FromSeconds(Request?.TimeoutSeconds ?? 120), cancellationToken);
    }

    // The returned observation is provisional. Only TryCommitResult can prepare output.
    public Task<AuthenticationOutcome> RunAsync(IProfileSource profiles,
        Func<ClientProfile, IAuthenticationProvider> createProvider) => lifetime.RunAsync(async token =>
        {
            if (Request is not null)
            {
                token.ThrowIfCancellationRequested();
                await profiles.ReadAsync(Request.ProfilePath, token).ConfigureAwait(false);
            }

            // Red seam: Profile semantics and provider composition are not implemented.
            return new(null, AuthenticationFailure.InternalFailure);
        });

    public bool TryCommitResult(out SerializedResult? result)
    {
        result = null;
        if (!lifetime.TryCommit(out var outcome)) return false;
        result = ResultProjection.Serialize(outcome!);
        return true;
    }

    public void Dispose() => lifetime.Dispose();
}
