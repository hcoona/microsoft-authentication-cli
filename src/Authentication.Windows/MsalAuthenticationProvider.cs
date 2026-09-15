using Authentication.Core;
using Microsoft.Identity.Client;

namespace Authentication.Windows;

internal sealed class MsalAuthenticationProvider : IAuthenticationProvider
{
    private const string PersonalHomeTenant = "9188040d-6c67-4c5b-b112-36a304b66dad";
    private const string TransferTenant = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";
    private readonly IMsalSession session;
    private readonly bool legacy;
    private readonly string initialTenant;

    private MsalAuthenticationProvider(IMsalSession session, bool legacy, string initialTenant)
    {
        this.session = session;
        this.legacy = legacy;
        this.initialTenant = initialTenant;
    }

    internal static IAuthenticationProvider Initialize(ClientProfile profile,
        AuthenticationRequest request, IMsalSessionFactory sessions, IMsalHttpClientFactory http,
        Action<CancellationToken> restrictDllSearch, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            restrictDllSearch(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            var legacy = profile.Integration == "visual-studio-legacy-wam";
            var tenant = request.ExactTenant?.ToString("D") ?? (legacy ? "organizations" : "common");
            var settings = new MsalClientSettings(profile.ClientId,
                "https://login.microsoftonline.com/" + tenant,
                "ms-appx-web://microsoft.aad.brokerplugin/" + profile.ClientId,
                ListOperatingSystemAccounts: true, MsaPassthrough: legacy);
            var session = sessions.Create(settings, http, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return new MsalAuthenticationProvider(session, legacy, tenant);
        }
        catch (Exception exception)
        {
            throw MsalBoundary.MapFailure(exception, cancellationToken);
        }
    }

    public async Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var accounts = await session.GetAccountsAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return accounts.Select(account => new ProviderAccount(account.Username, account)).ToArray();
        }
        catch (Exception exception)
        {
            throw MsalBoundary.MapFailure(exception, cancellationToken);
        }
    }

    public async Task<TokenCandidate> AcquireSilentAsync(AuthenticationRequest request,
        ProviderAccount account, Guid operationId, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var selected = (IAccount)account.Handle;
            // Only legacy silent routing without an exact resource tenant uses the
            // selected account's home tenant. Preserve the actual account handle.
            var tenant = legacy && request.ExactTenant is null
                && string.Equals(selected.HomeAccountId?.TenantId, PersonalHomeTenant,
                    StringComparison.OrdinalIgnoreCase) ? TransferTenant : initialTenant;
            var operation = new MsalSilentOperation(request.Scopes, selected, tenant, operationId);
            var result = await session.AcquireSilentAsync(operation, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return MsalBoundary.Project(result, operationId);
        }
        catch (Exception exception)
        {
            throw MsalBoundary.MapFailure(exception, cancellationToken);
        }
    }

    public async Task<TokenCandidate> AcquireInteractiveAsync(AuthenticationRequest request,
        ProviderAccount? account, string? claims, nint parentWindow, Guid operationId,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var selected = account is null ? null : (IAccount)account.Handle;
            var operation = new MsalInteractiveOperation(request.Scopes, selected,
                selected is null ? request.AccountEmail : null, initialTenant,
                claims, parentWindow, operationId);
            var result = await session.AcquireInteractiveAsync(operation, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return MsalBoundary.Project(result, operationId);
        }
        catch (Exception exception)
        {
            throw MsalBoundary.MapFailure(exception, cancellationToken);
        }
    }
}
