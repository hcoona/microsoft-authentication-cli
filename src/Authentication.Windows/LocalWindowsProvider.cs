using Authentication.Core;

namespace Authentication.Windows;

// Observations remain synchronous on the actual request or UI thread. The native
// implementation must preserve the original token around every individual query.
internal interface IWindowsHostAdmission
{
    void Admit(CancellationToken cancellationToken);
    void Recheck(CancellationToken cancellationToken);
}

// Inert initial baseline for the local-provider admission scenarios. The later
// implementation will guard initialization and each provider effect here. No real
// environment observer or MSAL initializer is supplied by this increment.
internal sealed class LocalWindowsProvider : IAuthenticationProvider
{
    internal LocalWindowsProvider(IWindowsHostAdmission admission,
        Func<CancellationToken, IAuthenticationProvider> initialize)
    {
        ArgumentNullException.ThrowIfNull(admission);
        ArgumentNullException.ThrowIfNull(initialize);
    }

    public Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromException<IReadOnlyList<ProviderAccount>>(Unavailable());
    }

    public Task<TokenCandidate> AcquireSilentAsync(AuthenticationRequest request,
        ProviderAccount account, Guid operationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromException<TokenCandidate>(Unavailable());
    }

    public Task<TokenCandidate> AcquireInteractiveAsync(AuthenticationRequest request,
        ProviderAccount? account, string? claims, nint parentWindow, Guid operationId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromException<TokenCandidate>(Unavailable());
    }

    private static ProviderFailureException Unavailable() =>
        new(AuthenticationFailure.MechanismUnavailable);
}
