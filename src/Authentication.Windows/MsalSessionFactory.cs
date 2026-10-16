using Authentication.Core;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensibility;

namespace Authentication.Windows;

internal sealed class MsalSessionFactory : IMsalSessionFactory
{
    private readonly WindowsMechanismTrace? trace;
    internal MsalSessionFactory(WindowsMechanismTrace? trace = null) => this.trace = trace;
    public IMsalSession Create(MsalClientSettings settings, IMsalHttpClientFactory http,
        CancellationToken cancellationToken)
    {
        var application = BuildApplication(settings, http, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var available = application.IsBrokerAvailable();
        cancellationToken.ThrowIfCancellationRequested();
        if (!available)
        {
            trace?.Record(WindowsMechanismFailure.BrokerUnavailable);
            throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable);
        }
        return new Session(application, trace);
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
            .WithBroker(Broker(settings))
            .Build();
        cancellationToken.ThrowIfCancellationRequested();
        return application;
    }

    // The fixed broker title is one of the unofficial-identity surfaces; scenarios
    // assert it on the exact options the application is built with.
    internal static BrokerOptions Broker(MsalClientSettings settings) =>
        new(BrokerOptions.OperatingSystems.Windows)
        {
            ListOperatingSystemAccounts = settings.ListOperatingSystemAccounts,
            MsaPassthrough = settings.MsaPassthrough,
            Title = "Unofficial hcoona/microsoft-authentication-cli",
        };

    // Pinned RuntimeBroker chooses its sign-in route (SignInInteractivelyAsync) only
    // when no account is bound. Forced interaction therefore binds no account but
    // supplies the requested email as the login hint, which may only pre-fill the
    // WAM interactive UI. Forced interaction requires WAM to present that UI; MSAL
    // documents the hint as avoiding select-account dialogs, so a skipped UI would be
    // a defect pending real-host confirmation. The hint is not a selector: final
    // validation still rejects any other returned account.
    internal static AcquireTokenInteractiveParameterBuilder BuildInteractiveRequest(
        PublicClientApplication application, MsalInteractiveOperation operation,
        WindowsMechanismTrace? trace, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var builder = application.AcquireTokenInteractive(operation.Scopes)
            .WithCorrelationId(operation.CorrelationId)
            .WithParentActivityOrWindow(operation.ParentWindow)
            .WithCustomWebUi(new RejectingWebUi(trace));
        if (RestrictiveTenant(operation.Tenant) is { } tenant)
            builder.WithTenantId(tenant);
        if (operation.ForceInteractive)
        {
            if (operation.Account is not null)
                throw new InvalidOperationException("A forced interactive operation must not bind an account.");
            builder.WithLoginHint(RequiredHint(operation));
        }
        else if (operation.Account is { } account)
            builder.WithAccount(account);
        else
            builder.WithLoginHint(RequiredHint(operation));
        if (operation.Claims is { } claims)
            builder.WithClaims(claims);
        return builder;
    }

    private static string RequiredHint(MsalInteractiveOperation operation) =>
        operation.LoginHint
        ?? throw new InvalidOperationException("The interactive operation requires a login hint.");

    private static string? RestrictiveTenant(string tenant)
    {
        // Named audiences remain on the application; request overrides must narrow it.
        if (tenant is "common" or "organizations")
            return null;
        if (!Guid.TryParseExact(tenant, "D", out _))
            throw new InvalidOperationException("The MSAL operation requires an admitted tenant.");
        return tenant;
    }

    private sealed class Session(PublicClientApplication application, WindowsMechanismTrace? trace) : IMsalSession
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
            var builder = BuildInteractiveRequest(application, operation, trace, cancellationToken);
            return builder.ExecuteAsync(cancellationToken);
        }
    }
}
