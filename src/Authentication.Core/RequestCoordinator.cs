namespace Authentication.Core;

public sealed class RequestCoordinator(IAuthenticationProvider provider, IRequestHost host,
    AuthenticationTrace? trace = null)
{
    private readonly IAuthenticationProvider provider = provider;
    private readonly IRequestHost host = host;

    public async Task<AuthenticationOutcome> AuthenticateAsync(
        AuthenticationRequest request,
        CancellationToken cancellationToken = default)
    {
        using var ownedTrace = trace is null ? AuthenticationTrace.Start() : null;
        var observation = trace ?? ownedTrace!;
        var closeOwnedUi = false;
        var interactive = false;
        AuthenticationOutcome outcome;
        try
        {
            outcome = await AcquireAsync();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            outcome = new(null, AuthenticationFailure.Cancelled);
        }
        catch (ProviderFailureException exception)
        {
            outcome = new(null, SafeFailure(exception.Failure), Interactive: interactive, Reason: exception.Reason);
        }
        catch (Exception)
        {
            outcome = new(null, AuthenticationFailure.InternalFailure, Interactive: interactive);
        }

        if (closeOwnedUi)
        {
            try
            {
                using var phase = observation.Begin(AuthenticationStage.InteractionClose);
                await host.CloseInteractionAsync();
            }
            catch (Exception)
            {
                // A cleanup fault cannot expose a token or replace an existing failure.
                // The process host must still enforce its finite shutdown allowance.
                if (outcome.Success is not null)
                {
                    outcome = new(null, AuthenticationFailure.InternalFailure, Interactive: interactive);
                }
            }
        }

        return cancellationToken.IsCancellationRequested
            ? new(null, AuthenticationFailure.Cancelled, Interactive: interactive)
            : outcome;

        async Task<AuthenticationOutcome> AcquireAsync()
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<ProviderAccount> accounts;
            using (observation.Begin(AuthenticationStage.AccountDiscovery))
                accounts = await provider.GetAccountsAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
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

            string? claims = null;
            var interactionReason = AuthenticationReason.None;
            if (selected is not null)
            {
                try
                {
                    var silentOperation = Guid.NewGuid();
                    TokenCandidate candidate;
                    using (observation.Begin(AuthenticationStage.SilentAcquisition))
                        candidate = await provider.AcquireSilentAsync(request, selected, silentOperation, cancellationToken);
                    cancellationToken.ThrowIfCancellationRequested();
                    return ValidateCandidate(request, candidate, silentOperation, interactive: false, observation);
                }
                catch (ProviderFailureException exception) when (exception.Failure == AuthenticationFailure.InteractionRequired)
                {
                    claims = exception.Claims;
                    interactionReason = exception.Reason;
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (!request.InteractionAllowed)
            {
                return new(null, AuthenticationFailure.InteractionRequired, Reason: interactionReason);
            }

            closeOwnedUi = true;
            nint parent;
            using (observation.Begin(AuthenticationStage.InteractionOpen))
                parent = await host.OpenInteractionAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (parent == 0)
            {
                return new(null, AuthenticationFailure.MechanismUnavailable);
            }

            interactive = true;
            var interactiveOperation = Guid.NewGuid();
            TokenCandidate interactiveCandidate;
            using (observation.Begin(AuthenticationStage.InteractiveAcquisition))
                interactiveCandidate = await provider.AcquireInteractiveAsync(
                    request, selected, claims, parent, interactiveOperation, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return ValidateCandidate(request, interactiveCandidate, interactiveOperation, interactive: true, observation);
        }
    }

    private AuthenticationOutcome ValidateCandidate(
        AuthenticationRequest request, TokenCandidate? candidate, Guid operationId, bool interactive,
        AuthenticationTrace observation)
    {
        using var phase = observation.Begin(AuthenticationStage.CandidateValidation);
        if (candidate is null || string.IsNullOrEmpty(candidate.AccessToken)
            || !string.Equals(candidate.Email, request.AccountEmail, StringComparison.OrdinalIgnoreCase)
            || candidate.Tenant is null
            || (request.ExactTenant is not null && candidate.Tenant != request.ExactTenant)
            || string.IsNullOrEmpty(candidate.TokenType)
            || candidate.ExpiresOn <= host.Clock.GetUtcNow()
            || candidate.OperationId != operationId
            || candidate.Scopes is null || candidate.Scopes.Any(string.IsNullOrEmpty)
            || !SatisfiesScopes(request.Scopes, candidate.Scopes))
        {
            return new(null, AuthenticationFailure.IdentityValidationFailed, Interactive: interactive);
        }

        return new(candidate, null, PersistenceUnconfirmed: true, Interactive: interactive);
    }

    private static AuthenticationFailure SafeFailure(AuthenticationFailure failure) => failure switch
    {
        AuthenticationFailure.InteractionRequired or AuthenticationFailure.AccountAmbiguous
            or AuthenticationFailure.IdentityValidationFailed or AuthenticationFailure.InvalidRequest
            or AuthenticationFailure.Cancelled or AuthenticationFailure.Denied
            or AuthenticationFailure.MechanismUnavailable or AuthenticationFailure.TemporarilyUnavailable
            or AuthenticationFailure.Timeout => failure,
        _ => AuthenticationFailure.InternalFailure,
    };

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
