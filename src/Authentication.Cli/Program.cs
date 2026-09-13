using Authentication.Core;
using Authentication.Windows;

namespace Authentication.Cli;

internal static class Program
{
    private static int Main(string[] arguments)
    {
        var entry = TimeProvider.System.GetTimestamp();
        return WindowsProcess.Run(arguments, entry, new RequestHost(),
            _ => throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable));
    }

    // Real WAM and the owned interaction window remain a subsequent increment.
    private sealed class RequestHost : IRequestHost
    {
        public TimeProvider Clock => TimeProvider.System;
    }
}
