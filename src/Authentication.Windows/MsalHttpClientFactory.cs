using Microsoft.Identity.Client;

namespace Authentication.Windows;

internal sealed class MsalHttpClientFactory : IMsalHttpClientFactory, IDisposable
{
    private readonly HttpClient client;

    internal MsalHttpClientFactory(HttpMessageHandler transport) =>
        client = new HttpClient(new ManagedUserAgentHandler(transport), disposeHandler: true);

    public HttpClient GetHttpClient() => client;

    // The process owner disposes only after its request work has drained.
    public void Dispose() => client.Dispose();
}
