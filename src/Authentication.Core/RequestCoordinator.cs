namespace Authentication.Core;

public sealed class RequestCoordinator(IAuthenticationProvider provider, IRequestHost host)
{
    private readonly IAuthenticationProvider provider = provider;
    private readonly IRequestHost host = host;

    public Task<AuthenticationOutcome> AuthenticateAsync(
        AuthenticationRequest request,
        CancellationToken cancellationToken = default)
    {
        // Initial TDD admission: no provider operation is implemented yet. The first
        // scenario run must demonstrate the specified missing business behavior.
        _ = provider;
        _ = host;
        _ = request;
        _ = cancellationToken;
        return Task.FromResult(new AuthenticationOutcome(null, AuthenticationFailure.InternalFailure));
    }
}
