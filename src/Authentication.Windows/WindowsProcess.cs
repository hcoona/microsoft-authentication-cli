using Authentication.Core;

namespace Authentication.Windows;

// The initial rejecting boundary exists to execute the process acceptance cases
// before implementing standard-handle admission, result delivery, and shutdown.
public static class WindowsProcess
{
    public static int Run(string[] arguments, long entryTimestamp, IRequestHost host,
        Func<ClientProfile, IAuthenticationProvider> createProvider, IProfileSource? profiles = null) => 2;
}
