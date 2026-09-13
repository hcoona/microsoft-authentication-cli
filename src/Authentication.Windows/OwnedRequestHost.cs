using System.Runtime.CompilerServices;
using Authentication.Core;

[assembly: InternalsVisibleTo("Authentication.Windows.Scenarios")]

namespace Authentication.Windows;

// Inert scenario baseline. No window, thread, native call, or provider is started.
internal sealed class OwnedRequestHost : IRequestHost
{
    internal OwnedRequestHost(Func<Task> cancel, Action fault,
        Action<OwnedHostCheckpoint, nint>? checkpoint = null)
    {
        _ = cancel;
        _ = fault;
        _ = checkpoint;
    }

    public TimeProvider Clock => TimeProvider.System;
    internal Task Completion => Task.CompletedTask;
    internal void BindProfile(ClientProfile profile) => _ = profile;
    public Task<nint> OpenInteractionAsync(CancellationToken cancellationToken) => Task.FromResult<nint>(0);
    public Task CloseInteractionAsync() => Task.CompletedTask;
}

// These internal checkpoints control finite scheduling and callback faults in
// scenarios. They do not replace the native window or provider boundary.
internal enum OwnedHostCheckpoint
{
    ThreadStarted,
    HiddenParentCreated,
    MessageDispatch,
    NativeCleanupCompleted,
}
