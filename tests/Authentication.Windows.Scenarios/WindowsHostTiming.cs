namespace Authentication.Windows.Scenarios;

// Scenarios in this category assert wall-clock process bounds (QPC on the same
// Windows host). They are Windows host-timing evidence, run only on a Windows host
// and are not part of the Linux continuous-integration job.
internal static class WindowsHostTiming
{
    internal const string Category = "WindowsHostTiming";
}
