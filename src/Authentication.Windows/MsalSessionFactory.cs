using Authentication.Core;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensibility;

namespace Authentication.Windows;

internal sealed class MsalSessionFactory : IMsalSessionFactory
{
    public IMsalSession Create(MsalClientSettings settings, IMsalHttpClientFactory http,
        CancellationToken cancellationToken)
    {
        var application = BuildApplication(settings, http, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var available = application.IsBrokerAvailable();
        cancellationToken.ThrowIfCancellationRequested();
        if (!available)
            throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable);
        return new Session(application);
    }

    internal static PublicClientApplication BuildApplication(MsalClientSettings settings,
        IMsalHttpClientFactory http, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var application = (PublicClientApplication)PublicClientApplicationBuilder
            .Create(settings.ClientId.ToString("D"))
            .WithAuthority(settings.Authority)
            .WithRedirectUri(settings.RedirectUri)
            .WithHttpClientFactory(http)
            .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
            {
                ListOperatingSystemAccounts = settings.ListOperatingSystemAccounts,
                MsaPassthrough = settings.MsaPassthrough,
            })
            .Build();
        cancellationToken.ThrowIfCancellationRequested();
        return application;
    }

    private sealed class Session(PublicClientApplication application) : IMsalSession
    {
        public async Task<IReadOnlyList<IAccount>> GetAccountsAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var accounts = (await application.GetAccountsAsync(cancellationToken)).ToArray();
            cancellationToken.ThrowIfCancellationRequested();
            return accounts;
        }

        public Task<AuthenticationResult> AcquireSilentAsync(MsalSilentOperation operation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var builder = application.AcquireTokenSilent(operation.Scopes, operation.Account)
                .WithCorrelationId(operation.CorrelationId);
            if (RestrictiveTenant(operation.Tenant) is { } tenant)
                builder.WithTenantId(tenant);
            return builder.ExecuteAsync(cancellationToken);
        }

        public Task<AuthenticationResult> AcquireInteractiveAsync(MsalInteractiveOperation operation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var builder = application.AcquireTokenInteractive(operation.Scopes)
                .WithCorrelationId(operation.CorrelationId)
                .WithParentActivityOrWindow(operation.ParentWindow)
                .WithCustomWebUi(new RejectingWebUi());
            if (RestrictiveTenant(operation.Tenant) is { } tenant)
                builder.WithTenantId(tenant);
            if (operation.Account is { } account)
                builder.WithAccount(account);
            else
                builder.WithLoginHint(operation.LoginHint
                    ?? throw new InvalidOperationException("The interactive operation requires a login hint."));
            if (operation.Claims is { } claims)
                builder.WithClaims(claims);
            return builder.ExecuteAsync(cancellationToken);
        }

        private static string? RestrictiveTenant(string tenant)
        {
            // Named audiences remain on the application; request overrides must narrow it.
            if (tenant is "common" or "organizations")
                return null;
            if (!Guid.TryParseExact(tenant, "D", out _))
                throw new InvalidOperationException("The MSAL operation requires an admitted tenant.");
            return tenant;
        }
    }
}
