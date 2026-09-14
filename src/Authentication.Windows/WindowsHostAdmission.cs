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

// Classifies synchronous local observations before initialization and later effects.
// Construction remains inert; the caller supplies the observation implementation.
internal sealed class WindowsHostAdmission : IWindowsHostAdmission
{
    private readonly IWindowsHostObservations observations;

    internal WindowsHostAdmission(IWindowsHostObservations observations)
    {
        ArgumentNullException.ThrowIfNull(observations);
        this.observations = observations;
    }

    public void Admit(CancellationToken cancellationToken)
    {
        var platform = Observe(observations.ReadPlatform, cancellationToken);
        Require(platform.IsWindows && platform.ProcessArchitecture == Architecture.X64
            && platform.OsArchitecture == Architecture.X64
            && platform.Version.Major == 10 && platform.Version.Minor == 0
            && platform.Version.Build >= 22000);
        Require(Observe(observations.ReadWorkstationProduct, cancellationToken) == true);
        Require(Observe(observations.ReadThreadIdentity, cancellationToken) == WindowsThreadIdentity.NoToken);

        var logon = Observe(observations.ReadOwnLogonAndStation, cancellationToken);
        Require(logon is
        {
            LogonType: 2 or 10 or 11 or 12,
            Identity: WindowsLogonIdentity.User,
            VisibleStation: true,
            StationUserMatches: true,
        });

        Require(Observe(observations.ReadSessionConnection, cancellationToken) == WindowsSessionConnection.Active);
        Require(Observe(observations.ReadInputDesktop, cancellationToken) == true);
    }

    public void Recheck(CancellationToken cancellationToken)
    {
        Require(Observe(observations.ReadThreadIdentity, cancellationToken) == WindowsThreadIdentity.NoToken);
        Require(Observe(observations.ReadSessionConnection, cancellationToken) == WindowsSessionConnection.Active);
        Require(Observe(observations.ReadInputDesktop, cancellationToken) == true);
    }

    private static T Observe<T>(Func<CancellationToken, T> observation, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        T result;
        try
        {
            result = observation(cancellationToken);
        }
        catch
        {
            // Preserve original cancellation even when an observation faults.
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }

        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    private static void Require(bool eligible)
    {
        if (!eligible)
            throw new ProviderFailureException(AuthenticationFailure.MechanismUnavailable);
    }
}
