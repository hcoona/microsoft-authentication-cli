using Authentication.Core;
using Microsoft.Identity.Client;

namespace Authentication.Windows;

internal static class MsalAuthenticationProvider
{
    // Deliberately incomplete until the admitted adapter scenarios establish RED.
    // The default product entry point is unchanged and remains unavailable.
    internal static IAuthenticationProvider Initialize(ClientProfile profile,
        AuthenticationRequest request, IMsalSessionFactory sessions, IMsalHttpClientFactory http,
        Action<CancellationToken> restrictDllSearch, CancellationToken cancellationToken) =>
        throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable);
}
