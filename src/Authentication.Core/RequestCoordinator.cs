namespace Authentication.Core;

public sealed class RequestCoordinator(IAuthenticationProvider provider, IRequestHost host)
{
    private readonly IAuthenticationProvider provider = provider;
    private readonly IRequestHost host = host;

    public async Task<AuthenticationOutcome> AuthenticateAsync(
        AuthenticationRequest request,
        CancellationToken cancellationToken = default)
    {
        // Clock-driven candidate and lifetime rules follow the selected-account loop.
        _ = host;
        var accounts = await provider.GetAccountsAsync(cancellationToken);
        ProviderAccount? selected = null;
        foreach (var account in accounts)
        {
            if (!string.Equals(account.Email, request.AccountEmail, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (selected is not null)
            {
                return new(null, AuthenticationFailure.AccountAmbiguous);
            }

            selected = account;
        }

        if (selected is null)
        {
            return new(null, AuthenticationFailure.InteractionRequired);
        }

        var operationId = Guid.NewGuid();
        var candidate = await provider.AcquireSilentAsync(request, selected, operationId, cancellationToken);
        if (!string.Equals(candidate.Email, request.AccountEmail, StringComparison.OrdinalIgnoreCase)
            || (request.ExactTenant is not null && candidate.Tenant != request.ExactTenant))
        {
            return new(null, AuthenticationFailure.IdentityValidationFailed);
        }

        return new(candidate, null, PersistenceUnconfirmed: true);
    }
}
