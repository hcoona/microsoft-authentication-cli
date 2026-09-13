using Authentication.Core;

namespace Authentication.Windows;

// One invocation per process. The calling thread is the watchdog: dependency
// prefixes, callbacks, native I/O and cleanup never execute on that thread.
public static class WindowsProcess
{
    public static int Run(string[] arguments, long entryTimestamp, IRequestHost host,
        Func<ClientProfile, IAuthenticationProvider> createProvider, IProfileSource? profiles = null)
    {
        var process = new ProcessState(entryTimestamp);
        try
        {
            new Thread(() => Execute(process, arguments, entryTimestamp, host, createProvider,
                profiles ?? new WindowsProfileSource())) { IsBackground = true }.Start();

            while (true)
            {
                var completion = process.Completion;
                if (process.ExceededBound(completion?.Timestamp ?? TimeProvider.System.GetTimestamp()))
                {
                    WindowsStandardHandles.Terminate();
                    return 2;
                }
                if (completion is not null) return completion.ExitCode;
                Thread.Sleep(5);
            }
        }
        catch (Exception)
        {
            WindowsStandardHandles.Terminate();
            return 2;
        }
    }

    private static void Execute(ProcessState process, string[] arguments, long entryTimestamp,
        IRequestHost host, Func<ClientProfile, IAuthenticationProvider> createProvider, IProfileSource profiles)
    {
        var exitCode = 2;
        RequestInvocation? invocation = null;
        WindowsLifetimePipe? pipe = null;
        ConsoleCancelEventHandler cancelHandler = (_, notification) =>
        {
            notification.Cancel = true;
            try { _ = process.Cancel(); }
            catch (Exception) { }
        };
        try
        {
            if (arguments.Length == 1 && arguments[0] is "help" or "--help")
            {
                process.Ending();
                exitCode = WindowsStandardHandles.Write(WindowsStandardHandles.Output, Help) ? 0 : 2;
                return;
            }

            invocation = new RequestInvocation(arguments, host, entryTimestamp, process.CancellationToken);
            process.Publish(invocation);
            Console.CancelKeyPress += cancelHandler;
            if (invocation.Request?.CancelOnStdinClose == true)
            {
                pipe = new WindowsLifetimePipe(process.Cancel);
                pipe.Start();
            }

            _ = invocation.RunAsync(profiles, createProvider, pipe?.Admission).GetAwaiter().GetResult();
            if (!process.TryCommit(invocation, out var result)) return;
            pipe?.Stop();
            WindowsDiagnostics.Completed(result!, invocation.Request?.TelemetryStderr == true, entryTimestamp);
            exitCode = WindowsStandardHandles.Write(WindowsStandardHandles.Output, result!.Utf8Json)
                ? result.ExitCode : 2;
        }
        catch (Exception)
        {
            // Request-body exceptions already have the core's safe typed mapping.
            // Host/transport failure cannot fabricate a replacement result.
            process.Ending();
            exitCode = 2;
        }
        finally
        {
            var drained = false;
            try
            {
                Console.CancelKeyPress -= cancelHandler;
                pipe?.Stop();
                // Dispose also terminates an invocation that failed before Run.
                // Pending operations/callbacks retain the original process bound.
                invocation?.Dispose();
                invocation?.CompleteAsync().GetAwaiter().GetResult();
                pipe?.Completion.GetAwaiter().GetResult();
                process.CancellationCompletion.GetAwaiter().GetResult();
                drained = true;
            }
            catch (Exception)
            {
                process.Ending();
            }
            if (drained) process.Finish(exitCode);
        }
    }

    private static byte[] Help => """
        Microsoft authentication CLI

        Usage:
          authenticate --protocol 1 --profile <absolute-Windows-path>
            --account-email <full-email> --scope <scope>
            --interaction <non-interactive-only|interactive-if-needed>
            [--scope <scope> ...] [--tenant <common|tenant-guid>]
            [--timeout-seconds <1..600>] [--cancel-on-stdin-close]
            [--telemetry <off|stderr>]

        --profile selects an explicit, existing Client Profile file.
        --cancel-on-stdin-close requires a dedicated caller-owned lifetime pipe.
        Authentication writes one protocol 1 JSON result to stdout.
        """u8.ToArray().Concat(new byte[] { (byte)'\n' }).ToArray();

    private sealed record ProcessCompletion(int ExitCode, long Timestamp);

    private sealed class ProcessState(long entryTimestamp)
    {
        private readonly object commitment = new();
        private readonly CancellationTokenSource callerCancellation = new();
        private readonly TaskCompletionSource cancelled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private RequestInvocation? invocation;
        private ProcessCompletion? completion;
        private long cancellationTimestamp = long.MinValue;
        private long endingTimestamp = long.MinValue;
        private int timeoutSeconds = 120;

        internal CancellationToken CancellationToken => callerCancellation.Token;
        internal ProcessCompletion? Completion => Volatile.Read(ref completion);
        internal Task CancellationCompletion => Volatile.Read(ref cancellationTimestamp) == long.MinValue
            ? Task.CompletedTask : cancelled.Task;

        internal void Publish(RequestInvocation request)
        {
            Volatile.Write(ref timeoutSeconds, request.Request?.TimeoutSeconds ?? 120);
            Volatile.Write(ref invocation, request);
        }

        internal Task Cancel()
        {
            var observed = TimeProvider.System.GetTimestamp();
            lock (commitment)
            {
                if (cancellationTimestamp == long.MinValue)
                {
                    Volatile.Write(ref cancellationTimestamp, observed);
                    _ = ObserveCancellationAsync();
                }
            }
            return cancelled.Task;
        }

        private async Task ObserveCancellationAsync()
        {
            try { await callerCancellation.CancelAsync().ConfigureAwait(false); }
            catch (Exception) { }
            cancelled.TrySetResult();
        }

        internal bool TryCommit(RequestInvocation request, out SerializedResult? result)
        {
            // A cancellation observation and result commitment cannot pass each
            // other between the host latch and the lifetime's caller-token check.
            // This worker-only lock never encloses provider work or transport I/O.
            lock (commitment) return request.TryCommitResult(out result);
        }

        internal void Ending() => Interlocked.CompareExchange(ref endingTimestamp,
            TimeProvider.System.GetTimestamp(), long.MinValue);

        internal bool ExceededBound(long timestamp)
        {
            var clock = TimeProvider.System;
            if (clock.GetElapsedTime(entryTimestamp, timestamp)
                > TimeSpan.FromSeconds(Volatile.Read(ref timeoutSeconds) + 1)) return true;

            var terminal = Volatile.Read(ref invocation)?.TerminalTimestamp;
            var cancellation = Volatile.Read(ref cancellationTimestamp);
            var ending = Volatile.Read(ref endingTimestamp);
            return terminal is { } selected && clock.GetElapsedTime(selected, timestamp) > TimeSpan.FromSeconds(1)
                || cancellation != long.MinValue && clock.GetElapsedTime(cancellation, timestamp) > TimeSpan.FromSeconds(1)
                || ending != long.MinValue && clock.GetElapsedTime(ending, timestamp) > TimeSpan.FromSeconds(1);
        }

        internal void Finish(int exitCode) => Volatile.Write(ref completion,
            new ProcessCompletion(exitCode, TimeProvider.System.GetTimestamp()));
    }
}
