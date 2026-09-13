using Microsoft.Testing.Platform.Builder;

namespace Authentication.Windows.Scenarios;

internal static class Program
{
    private static async Task<int> Main(string[] arguments)
    {
        var entry = TimeProvider.System.GetTimestamp();
        if (arguments.Length >= 2 && arguments[0] == "--scenario-child")
        {
            return ProcessChild.Run(arguments[1], arguments[2..], entry);
        }

        var builder = await TestApplication.CreateBuilderAsync(arguments);
        builder.AddSelfRegisteredExtensions(arguments);
        using var application = await builder.BuildAsync();
        return await application.RunAsync();
    }
}
