using Authentication.Core;

namespace Authentication.Windows;

// Incomplete source for the separately admitted Windows file-scenario red run.
// No file or provider operation is performed by this initial implementation.
public sealed class WindowsProfileSource : IProfileSource
{
    public Task<ReadOnlyMemory<byte>> ReadAsync(string path, CancellationToken cancellationToken) =>
        Task.FromException<ReadOnlyMemory<byte>>(new IOException("Profile is unavailable."));
}
