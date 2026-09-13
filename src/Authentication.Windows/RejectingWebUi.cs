using Authentication.Core;
using Microsoft.Identity.Client.Extensibility;

namespace Authentication.Windows;

public sealed class RejectingWebUi : ICustomWebUi
{
    // A lost broker cannot enable browser navigation through MSAL's fallback callback.
    public Task<Uri> AcquireAuthorizationCodeAsync(Uri authorizationUri, Uri redirectUri,
        CancellationToken cancellationToken) =>
        Task.FromException<Uri>(new ProviderFailureException(AuthenticationFailure.MechanismUnavailable));
}
