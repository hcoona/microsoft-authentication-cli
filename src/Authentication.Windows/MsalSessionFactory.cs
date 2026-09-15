using Authentication.Core;
using Microsoft.Identity.Client;

namespace Authentication.Windows;

internal sealed class MsalSessionFactory : IMsalSessionFactory
{
    public IMsalSession Create(MsalClientSettings settings, IMsalHttpClientFactory http,
        CancellationToken cancellationToken)
    {
        _ = BuildApplication(settings, http, cancellationToken);
        throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable);
    }

    internal static PublicClientApplication BuildApplication(MsalClientSettings settings,
        IMsalHttpClientFactory http, CancellationToken cancellationToken)
    {
        // Intentional RED baseline: construction and original cancellation are absent.
        return null!;
    }
}
