namespace Authentication.Core;

public sealed class RequestCoordinator(IAuthenticationProvider provider, IRequestHost host)
{
    private readonly IAuthenticationProvider provider = provider;
    private readonly IRequestHost host = host;

    public async Task<AuthenticationOutcome> AuthenticateAsync(
        AuthenticationRequest request,
        CancellationToken cancellationToken = default)
    {
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
        if (string.IsNullOrEmpty(candidate.AccessToken)
            || !string.Equals(candidate.Email, request.AccountEmail, StringComparison.OrdinalIgnoreCase)
            || candidate.Tenant is null
            || (request.ExactTenant is not null && candidate.Tenant != request.ExactTenant)
            || string.IsNullOrEmpty(candidate.TokenType)
            || candidate.ExpiresOn <= host.Clock.GetUtcNow()
            || candidate.OperationId != operationId
            || !SatisfiesScopes(request.Scopes, candidate.Scopes))
        {
            return new(null, AuthenticationFailure.IdentityValidationFailed);
        }

        return new(candidate, null, PersistenceUnconfirmed: true);
    }

    private static bool SatisfiesScopes(IReadOnlyList<string> requested, IReadOnlyList<string> granted)
    {
        // Admission has already established one resource and isolated /.default.
        // The operation ID above binds its result to that original resource request;
        // providers need not return the literal /.default spelling among grants.
        if (requested.Count == 1 && requested[0].EndsWith("/.default", StringComparison.Ordinal))
        {
            return true;
        }

        return requested.All(scope => granted.Contains(scope, StringComparer.Ordinal));
    }
}
