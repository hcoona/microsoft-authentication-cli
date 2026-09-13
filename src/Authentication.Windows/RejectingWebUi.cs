using Authentication.Core;
using Microsoft.Identity.Client.Extensibility;

namespace Authentication.Windows;

public sealed class RejectingWebUi : ICustomWebUi
{
    // This baseline fails safely without navigating or returning an authorization URI.
    public Task<Uri> AcquireAuthorizationCodeAsync(Uri authorizationUri, Uri redirectUri,
        CancellationToken cancellationToken) =>
        Task.FromException<Uri>(new ProviderFailureException(AuthenticationFailure.InternalFailure));
}
