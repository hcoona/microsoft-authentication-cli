namespace Authentication.Core;

// Application lifetime seam. RunAsync supplies a provisional observation; only the
// outcome returned by TryCommit may be delivered through the public result channel.
// This initial pass-through intentionally lacks the deadline and terminal policy.
public sealed class RequestLifetime : IDisposable
{
    private readonly CancellationToken cancellationToken;
    private AuthenticationOutcome? outcome;
    private bool committed;

    public RequestLifetime(TimeProvider clock, long entryTimestamp, TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        this.cancellationToken = cancellationToken;
    }

    public async Task<AuthenticationOutcome> RunAsync(Func<CancellationToken, Task<AuthenticationOutcome>> operation)
    {
        outcome = await operation(cancellationToken);
        return outcome;
    }

    public bool TryCommit(out AuthenticationOutcome? result)
    {
        result = null;
        if (committed || outcome is null) return false;
        committed = true;
        result = outcome;
        return true;
    }

    public void Dispose()
    {
    }
}
