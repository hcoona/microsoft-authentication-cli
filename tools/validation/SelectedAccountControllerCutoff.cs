using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

// Public validation code only. The accepted exact call supplies the newly
// created controller Process; this type never selects or opens a PID.
public sealed class SelectedAccountControllerCutoff
{
    private const uint SynchronizeAndTerminate = 0x00100001;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;
    private static SelectedAccountControllerCutoff retainedFailure;
    private readonly object gate = new object();
    private readonly long originalStart;
    private readonly long admissionEnd;
    private readonly long primaryEnd;
    private readonly long originalEnd;
    private Process originalOwner;
    private IntPtr originalHandle;
    private IntPtr duplicateHandle;
    private Timer timer;
    private ManualResetEvent fallbackDone;
    private ManualResetEvent timerDrained;
    private int bindingClaimed;
    // 0: available; 1: sole stop claimed; 2: observed exit/no created role.
    private int actionState;
    private int finishing;
    private int failed;
    private int armed;
    private int bound;
    private int fallbackFired;
    private int terminationAttempted;
    private int terminationInitiated;
    private int exitObserved;
    private int callbackComplete;
    private int cleanupComplete;
    private long stopTicks;
    private long observedExitTicks;
    private long cleanupTicks;

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source,
        IntPtr targetProcess, out IntPtr target, uint access,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetStdHandle(uint standardHandle);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    public static bool HasExistingConsoleInput()
    {
        // Borrow the current standard input only; do not close it, read input,
        // attach/create a console, or change console mode.
        IntPtr input = GetStdHandle(4294967286U);
        uint mode;
        return input != IntPtr.Zero && input != new IntPtr(-1) &&
            GetConsoleMode(input, out mode);
    }

    private static bool Read(int value) { return value != 0; }
    private bool Before(long end)
    {
        long now = Stopwatch.GetTimestamp();
        return now >= originalStart && now < end;
    }
    private int Remaining(long end, int maximum)
    {
        long now = Stopwatch.GetTimestamp();
        if (now < originalStart || now >= end) return 0;
        double milliseconds = Math.Floor(1000.0 * (end - now) / Stopwatch.Frequency);
        return (int)Math.Max(0, Math.Min(maximum, milliseconds));
    }
    private void Fail() { Interlocked.Exchange(ref failed, 1); }
    private IntPtr Target(bool duplicateOnly)
    {
        // No I/O, native call or blocking operation occurs while holding this lock.
        lock (gate)
        {
            return duplicateHandle != IntPtr.Zero ? duplicateHandle :
                (duplicateOnly ? IntPtr.Zero : originalHandle);
        }
    }

    public SelectedAccountControllerCutoff(long invocationStartTicks)
    {
        if (Interlocked.CompareExchange(ref retainedFailure, null, null) != null)
            throw new InvalidOperationException("A previous cutoff remains incomplete.");
        if (!Environment.Is64BitProcess || Stopwatch.Frequency <= 0)
            throw new InvalidOperationException("Cutoff environment refused.");
        originalStart = invocationStartTicks;
        admissionEnd = checked(originalStart + 20L * Stopwatch.Frequency);
        primaryEnd = checked(originalStart + 175L * Stopwatch.Frequency);
        originalEnd = checked(originalStart + 180L * Stopwatch.Frequency);
        if (originalStart <= 0 || !Before(admissionEnd))
            throw new InvalidOperationException("Cutoff epoch refused.");
        try
        {
            fallbackDone = new ManualResetEvent(false);
            timerDrained = new ManualResetEvent(false);
            timer = new Timer(Fallback, null, Timeout.Infinite, Timeout.Infinite);
            int due = checked((int)Math.Ceiling(1000.0 *
                (primaryEnd - Stopwatch.GetTimestamp()) / Stopwatch.Frequency));
            if (due <= 0 || due > 175000 || !timer.Change(due, Timeout.Infinite) || !Before(admissionEnd))
                throw new InvalidOperationException("Cutoff arming refused.");
            Interlocked.Exchange(ref armed, 1);
        }
        catch
        {
            Fail();
            // There is no controller. Disarm and drain rather than abandoning a
            // timer whose arming call may have completed before an exception.
            Finish(false);
            throw new InvalidOperationException("Cutoff arming refused.");
        }
    }

    public bool BindOriginal(Process process)
    {
        if (process == null || Interlocked.CompareExchange(ref bindingClaimed, 1, 0) != 0)
        { Fail(); return false; }
        try
        {
            // Retain Process ownership before its handle accessor can fail.
            lock (gate) { originalOwner = process; }
            if (!Before(admissionEnd)) { Fail(); Retain(); return false; }
            IntPtr handle = process.Handle;
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            { Fail(); return false; }
            lock (gate) { originalOwner = process; originalHandle = handle; }
            IntPtr copy;
            IntPtr self = GetCurrentProcess();
            if (!DuplicateHandle(self, handle, self, out copy, SynchronizeAndTerminate, false, 0))
            { Fail(); return false; }
            lock (gate) { duplicateHandle = copy; }
            Interlocked.Exchange(ref bound, 1);
            if (copy == IntPtr.Zero || !Before(admissionEnd) ||
                Interlocked.CompareExchange(ref actionState, 0, 0) != 0)
            { Fail(); return false; }
            return true;
        }
        catch { Fail(); return false; }
    }

    private bool ObserveExit(IntPtr target)
    {
        if (target == IntPtr.Zero || !Before(originalEnd)) return false;
        uint result = WaitForSingleObject(target, 0);
        if (result == WaitObject0 && Before(originalEnd))
        {
            Interlocked.Exchange(ref observedExitTicks, Stopwatch.GetTimestamp());
            Interlocked.Exchange(ref exitObserved, 1);
            return true;
        }
        if (result != WaitTimeout) Fail();
        return false;
    }

    private bool StopOnce(IntPtr target, long end)
    {
        if (Interlocked.CompareExchange(ref actionState, 1, 0) != 0)
            return Interlocked.CompareExchange(ref actionState, 0, 0) == 2;
        if (target == IntPtr.Zero || !Before(end)) { Fail(); return false; }
        try
        {
            if (ObserveExit(target)) return true;
            if (!Before(end)) { Fail(); return false; }
            Interlocked.Exchange(ref stopTicks, Stopwatch.GetTimestamp());
            Interlocked.Exchange(ref terminationAttempted, 1);
            bool initiated = TerminateProcess(target, 125);
            if (initiated) Interlocked.Exchange(ref terminationInitiated, 1);
            if (!initiated || !Before(end)) { Fail(); return false; }
            return true;
        }
        catch { Fail(); return false; }
    }

    public bool StopPrimary()
    {
        // If duplication failed, the existing outer caller still retains this
        // exact original Process handle. Only this synchronous primary path may
        // use it; the timer never borrows it or reopens a process.
        return StopOnce(Target(false), primaryEnd);
    }

    public bool MarkObservedExit()
    {
        try
        {
            if (!ObserveExit(Target(false))) { Fail(); return false; }
            // Synchronize ordinary completion with the timer's sole stop claim.
            int previous = Interlocked.CompareExchange(ref actionState, 2, 0);
            return previous == 0 || previous == 2;
        }
        catch { Fail(); return false; }
    }

    private void Fallback(object ignored)
    {
        try
        {
            if (Interlocked.CompareExchange(ref actionState, 0, 0) == 2) return;
            Interlocked.Exchange(ref fallbackFired, 1);
            // This is a pure C# callback on a ThreadPool thread. It never calls
            // PowerShell, receipt I/O, a PID API or a shared-shell stop method.
            IntPtr target = Target(true);
            if (target == IntPtr.Zero || !Before(originalEnd)) { Fail(); return; }
            StopOnce(target, originalEnd);
            int remaining = Remaining(originalEnd, 5000);
            if (remaining <= 0) { Fail(); return; }
            uint result = WaitForSingleObject(target, (uint)remaining);
            if (result != WaitObject0 || !Before(originalEnd)) { Fail(); return; }
            Interlocked.Exchange(ref observedExitTicks, Stopwatch.GetTimestamp());
            Interlocked.Exchange(ref exitObserved, 1);
        }
        catch { Fail(); }
        finally
        {
            Interlocked.Exchange(ref callbackComplete, 1);
            try { fallbackDone.Set(); } catch { Fail(); }
        }
    }

    public bool Finish(bool controllerExited)
    {
        if (Interlocked.CompareExchange(ref finishing, 1, 0) != 0)
            return CleanupComplete && !Failed;
        try
        {
            IntPtr target = Target(false);
            bool exited = target != IntPtr.Zero && ObserveExit(target);
            if (controllerExited && !exited) Fail();
            if (exited)
                Interlocked.CompareExchange(ref actionState, 2, 0);
            else if (target == IntPtr.Zero)
            {
                bool created;
                lock (gate) { created = originalOwner != null; }
                if (created) { Fail(); Retain(); return false; }
                Interlocked.CompareExchange(ref actionState, 2, 0);
            }
            else
            {
                // Keep the one-shot fallback armed when a primary stop has not
                // produced observed exit. This wait drains that original lease;
                // it introduces no renewed cutoff or additional stop attempt.
                if (Before(primaryEnd)) StopPrimary();
                int remaining = Remaining(originalEnd, 180000);
                if (remaining <= 0 || fallbackDone == null || !fallbackDone.WaitOne(remaining))
                { Fail(); Retain(); return false; }
            }
            if (timer != null)
            {
                if (timerDrained == null || !timer.Dispose(timerDrained))
                { Fail(); Retain(); return false; }
                int remaining = Remaining(originalEnd, 180000);
                if (!timerDrained.WaitOne(remaining))
                { Fail(); Retain(); return false; }
                timer = null;
            }
            // Dispose(WaitHandle) has confirmed all queued callback completion.
            // The primary caller has returned from its own stop/wait before Finish.
            bool createdRole;
            lock (gate) { createdRole = originalOwner != null; }
            long exitTicks = Interlocked.Read(ref observedExitTicks);
            if (createdRole && (!ExitObserved || exitTicks < originalStart || exitTicks >= originalEnd))
            { Fail(); Retain(); return false; }
            IntPtr copy;
            lock (gate) { copy = duplicateHandle; }
            if (copy != IntPtr.Zero && !CloseHandle(copy))
            { Fail(); Retain(); return false; }
            lock (gate) { duplicateHandle = IntPtr.Zero; }
            ManualResetEvent done = fallbackDone;
            fallbackDone = null;
            if (done != null) done.Close();
            done = timerDrained;
            timerDrained = null;
            if (done != null) done.Close();
            // Lease-owned original Process disposal follows callback/native-wait
            // cleanup. Keep its owner attached if disposal fails or is late.
            Process owner;
            lock (gate) { owner = originalOwner; }
            if (owner != null)
            {
                if (!Before(originalEnd)) { Fail(); Retain(); return false; }
                owner.Dispose();
                if (!Before(originalEnd)) { Fail(); Retain(); return false; }
            }
            lock (gate) { originalOwner = null; originalHandle = IntPtr.Zero; }
            Interlocked.Exchange(ref cleanupTicks, Stopwatch.GetTimestamp());
            if (!Before(originalEnd)) Fail();
            Interlocked.Exchange(ref cleanupComplete, 1);
            return !Failed;
        }
        catch { Fail(); Retain(); return false; }
    }

    private void Retain()
    {
        // Preserve strong ownership if a callback/native wait may still be using
        // a handle. A later case is refused; no unsafe close or retry follows.
        Interlocked.CompareExchange(ref retainedFailure, this, null);
    }
    public long InvocationStartTicks { get { return originalStart; } }
    public bool Armed { get { return Read(Interlocked.CompareExchange(ref armed, 0, 0)); } }
    public bool Bound { get { return Read(Interlocked.CompareExchange(ref bound, 0, 0)); } }
    public bool StopClaimed { get { return Interlocked.CompareExchange(ref actionState, 0, 0) == 1; } }
    public bool FallbackFired { get { return Read(Interlocked.CompareExchange(ref fallbackFired, 0, 0)); } }
    public bool TerminationAttempted { get { return Read(Interlocked.CompareExchange(ref terminationAttempted, 0, 0)); } }
    public bool TerminationInitiated { get { return Read(Interlocked.CompareExchange(ref terminationInitiated, 0, 0)); } }
    public bool ExitObserved { get { return Read(Interlocked.CompareExchange(ref exitObserved, 0, 0)); } }
    public bool CallbackComplete { get { return Read(Interlocked.CompareExchange(ref callbackComplete, 0, 0)); } }
    public bool CleanupComplete { get { return Read(Interlocked.CompareExchange(ref cleanupComplete, 0, 0)); } }
    public bool Failed { get { return Read(Interlocked.CompareExchange(ref failed, 0, 0)); } }
    public long StopTicks { get { return Interlocked.Read(ref stopTicks); } }
    public long ObservedExitTicks { get { return Interlocked.Read(ref observedExitTicks); } }
    public long CleanupTicks { get { return Interlocked.Read(ref cleanupTicks); } }
}
