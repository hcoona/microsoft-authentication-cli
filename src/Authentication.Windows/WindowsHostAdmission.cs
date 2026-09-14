using System.Runtime.InteropServices;
using Authentication.Core;

namespace Authentication.Windows;

// This observation boundary supplies only the local facts used by admission. The
// native implementation owns its temporary handles/buffers and never exports them.
internal interface IWindowsHostObservations
{
    WindowsHostPlatform ReadPlatform(CancellationToken cancellationToken);
    bool? ReadWorkstationProduct(CancellationToken cancellationToken);
    WindowsThreadIdentity ReadThreadIdentity(CancellationToken cancellationToken);
    WindowsLocalLogon? ReadOwnLogonAndStation(CancellationToken cancellationToken);
    WindowsSessionConnection ReadSessionConnection(CancellationToken cancellationToken);
    bool? ReadInputDesktop(CancellationToken cancellationToken);
}

internal sealed record WindowsHostPlatform(bool IsWindows, Architecture ProcessArchitecture,
    Architecture OsArchitecture, Version Version);

internal enum WindowsThreadIdentity { NoToken, Impersonating, Unavailable }
internal enum WindowsLogonIdentity { Invalid, User, LocalSystem, LocalService, NetworkService }
internal enum WindowsSessionConnection { Unavailable, ZeroSession, Active, Inactive, Malformed }

internal sealed record WindowsLocalLogon(uint LogonType, WindowsLogonIdentity Identity,
    bool VisibleStation, bool? StationUserMatches);

// Inert red baseline. The native observations and admission implementation follow
// independent acceptance of the controlled scenario failures.
internal sealed class WindowsHostAdmission : IWindowsHostAdmission
{
    internal WindowsHostAdmission(IWindowsHostObservations observations)
    {
        ArgumentNullException.ThrowIfNull(observations);
    }

    public void Admit(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable);
    }

    public void Recheck(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable);
    }
}
