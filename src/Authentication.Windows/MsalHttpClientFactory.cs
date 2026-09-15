using Microsoft.Identity.Client;

namespace Authentication.Windows;

internal sealed class MsalHttpClientFactory : IMsalHttpClientFactory, IDisposable
{
    private readonly HttpMessageHandler handler;
    private readonly List<HttpClient> clients = [];

    internal MsalHttpClientFactory(HttpMessageHandler transport) =>
        handler = new ManagedUserAgentHandler(transport);

    // Deliberately lacks reuse until the admitted ownership scenario establishes RED.
    public HttpClient GetHttpClient()
    {
        var client = new HttpClient(handler, disposeHandler: false);
        clients.Add(client);
        return client;
    }

    public void Dispose()
    {
        foreach (var client in clients) client.Dispose();
        handler.Dispose();
    }
}
