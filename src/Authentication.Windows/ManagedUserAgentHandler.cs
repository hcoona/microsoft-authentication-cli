namespace Authentication.Windows;

public sealed class ManagedUserAgentHandler(HttpMessageHandler innerHandler) : DelegatingHandler(innerHandler)
{
    // Pass-through red baseline; the scenario supplies only an in-memory terminal handler.
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken) => base.SendAsync(request, cancellationToken);
}
