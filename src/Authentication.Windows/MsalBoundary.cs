using Authentication.Core;
using Microsoft.Identity.Client;

namespace Authentication.Windows;

// Inert baseline for admitted scenario-first development. No MSAL client is created.
public static class MsalBoundary
{
    public static ProviderFailureException MapFailure(Exception exception, CancellationToken cancellationToken) =>
        new(AuthenticationFailure.InternalFailure);

    public static TokenCandidate Project(AuthenticationResult result, Guid operationId) =>
        new(string.Empty, null, null, [], string.Empty, default, Guid.Empty);
}
