using System.Text;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Windows.Scenarios;

// Exact child selection and effects require their own accepted protocol. These
// scenarios exercise the production process with synthetic providers and real
// owned windows; no account, broker, token-cache or external UI operation occurs.
[TestClass]
[DoNotParallelize]
public sealed class OwnedProcessScenarios
{
    [TestMethod]
    public async Task NormalOwnedClosurePreservesSuccessAndDrains()
    {
        using var child = new ProcessFixture("host-success");
        await child.FinishAsync();
        RequireMarkers(child, "provider-ready", "candidate-returned", "host-closing",
            "native-cleanup-completed", "host-drained");
        AssertExit(child, 0);
        AssertSuccess(child);
        Assert.IsFalse(child.Marked("cancel-pending"));
        Assert.IsFalse(child.Marked("fault-pending"));
    }

    [TestMethod]
    public async Task LocalCancellationSuppressesSuccessBeforeDelayedNotification()
    {
        using var child = new ProcessFixture("host-cancel");
        await child.FinishAsync();
        RequireMarkers(child, "provider-ready", "host-closing", "cancel-pending", "candidate-returned",
            "after-commit", "cancel-drained");
        AssertOrdered(child, "cancel-pending", "candidate-returned", "after-commit", "cancel-forwarded");
        AssertFailure(child, "cancelled");
        AssertExit(child, 1);
    }

    [TestMethod]
    public async Task LocalHostFaultSuppressesSuccessBeforeDelayedNotification()
    {
        using var child = new ProcessFixture("host-fault");
        await child.FinishAsync();
        RequireMarkers(child, "provider-ready", "native-fault-injected", "fault-pending",
            "candidate-returned", "fault-drained");
        AssertOrdered(child, "fault-pending", "candidate-returned", "after-commit", "fault-drained");
        AssertFailure(child, "internal_failure");
        AssertExit(child, 1);
    }

    [TestMethod]
    public async Task CancellationDuringCreationSurvivesClosureFailure()
    {
        using var child = new ProcessFixture("host-create-cancel");
        await child.FinishAsync();
        RequireMarkers(child, "hidden-parent-created", "local-close-sent", "host-closing",
            "local-close-returned", "native-cleanup-completed");
        Assert.IsFalse(child.Marked("provider-ready"));
        AssertFailure(child, "cancelled");
        AssertExit(child, 2); // Failed owned cleanup cannot be marked normally drained.
        AssertExitBound(child, "host-closing");
    }

    [TestMethod]
    public async Task OrdinaryCreationFailureRemainsMechanismUnavailable()
    {
        using var child = new ProcessFixture("host-create-failure");
        await child.FinishAsync();
        RequireMarkers(child, "hidden-parent-created", "native-cleanup-completed", "host-drained");
        Assert.IsFalse(child.Marked("provider-ready"));
        Assert.IsFalse(child.Marked("cancel-pending"));
        AssertFailure(child, "mechanism_unavailable");
        AssertExit(child, 1);
    }

    [TestMethod]
    public async Task CleanupFaultAfterNormalClosureSuppressesUncommittedSuccess()
    {
        using var child = new ProcessFixture("host-fault-before-commit");
        await child.FinishAsync();
        RequireMarkers(child, "candidate-returned", "host-closing", "native-cleanup-completed",
            "cleanup-fault-injected", "fault-pending", "fault-drained");
        AssertOrdered(child, "host-closing", "fault-pending", "before-commit", "after-commit");
        AssertFailure(child, "internal_failure");
        AssertExit(child, 2);
        AssertExitBound(child, "host-closing");
    }

    [TestMethod]
    public async Task CleanupFaultAfterCommitCannotReplaceTheResult()
    {
        using var child = new ProcessFixture("host-fault-after-commit");
        await child.FinishAsync();
        RequireMarkers(child, "candidate-returned", "after-commit", "cleanup-fault-injected", "fault-drained");
        AssertOrdered(child, "after-commit", "cleanup-fault-injected", "fault-drained");
        AssertSuccess(child);
        AssertExit(child, 2);
        AssertExitBound(child, "host-closing");
    }

    [TestMethod]
    public async Task ProcessWaitsForTheActualOwnedThreadExit()
    {
        using var child = new ProcessFixture("host-ui-join");
        await child.FinishAsync();
        RequireMarkers(child, "native-cleanup-completed", "after-commit");
        AssertSuccess(child);
        AssertExit(child, 2);
        Assert.IsFalse(child.Marked("host-drained"));
        AssertExitBound(child, "host-closing");
    }

    [TestMethod]
    public async Task ProcessWaitsForTheOutgoingOwnedCallback()
    {
        using var child = new ProcessFixture("host-callback-drain");
        await child.FinishAsync();
        RequireMarkers(child, "cancel-pending", "native-cleanup-completed", "ui-thread-exited",
            "after-commit", "cancel-forwarded");
        AssertOrdered(child, "native-cleanup-completed", "ui-thread-exited", "before-commit");
        AssertOrdered(child, "cancel-pending", "candidate-returned", "after-commit", "cancel-forwarded");
        AssertFailure(child, "cancelled");
        AssertExit(child, 2);
        Assert.IsFalse(child.Marked("cancel-drained"));
        AssertExitBound(child, "host-closing");
    }

    [TestMethod]
    public async Task NormalClosureArmsTheBoundBeforeCoreTerminalSelection()
    {
        using var child = new ProcessFixture("host-close-stall");
        await child.FinishAsync();
        RequireMarkers(child, "provider-ready", "candidate-returned", "host-closing");
        AssertExit(child, 2);
        AssertExitBound(child, "host-closing");
        Assert.AreEqual(0, child.Output.Length);
        Assert.IsFalse(child.Marked("before-commit"));
    }

    private static void RequireMarkers(ProcessFixture child, params string[] names)
    {
        Assert.IsTrue(child.Marked("entered"), "Actual controlled entry is required.");
        foreach (var name in names)
            Assert.IsTrue(child.Marked(name), "The required actual state was not observed: " + name);
    }

    private static void AssertOrdered(ProcessFixture child, params string[] names)
    {
        for (var index = 1; index < names.Length; index++)
            Assert.IsTrue(child.MarkerTimestamp(names[index - 1]) <= child.MarkerTimestamp(names[index]),
                "The required actual event ordering was not established.");
    }

    private static void AssertExit(ProcessFixture child, uint code)
    {
        Assert.IsFalse(child.Forced, "The product must end before fixture enforcement.");
        Assert.AreEqual(code, child.ExitCode);
        Assert.AreEqual(0, child.Error.Length);
    }

    private static void AssertExitBound(ProcessFixture child, string firstEnding)
    {
        var start = child.MarkerTimestamp(firstEnding);
        Assert.IsTrue(start > 0 && child.ExitObservedTimestamp >= start);
        // Preserve the accepted QPC clock basis and 100 ms observation tolerance;
        // the product still has one second, independently of the fixture's waits.
        Assert.IsTrue(TimeProvider.System.GetElapsedTime(start, child.ExitObservedTimestamp)
            <= TimeSpan.FromMilliseconds(1100), "Owned shutdown exceeded the measured local bound.");
    }

    private static void AssertFailure(ProcessFixture child, string outcome)
    {
        using var json = ParseOne(child.Output);
        Assert.AreEqual(outcome, json.RootElement.GetProperty("outcome").GetString());
        Assert.AreEqual(outcome, json.RootElement.GetProperty("reason").GetString());
        CollectionAssert.AreEquivalent(new[] { "protocol", "outcome", "reason" },
            json.RootElement.EnumerateObject().Select(property => property.Name).ToArray());
    }

    private static void AssertSuccess(ProcessFixture child)
    {
        using var json = ParseOne(child.Output);
        var result = json.RootElement;
        Assert.AreEqual("success", result.GetProperty("outcome").GetString());
        Assert.AreEqual(ProcessChild.Token, result.GetProperty("accessToken").GetString());
        Assert.AreEqual(ProcessChild.Email, result.GetProperty("accountEmail").GetString());
        Assert.AreEqual(ProcessChild.Tenant, result.GetProperty("tenantId").GetString());
        Assert.AreEqual("interactive", result.GetProperty("interaction").GetString());
    }

    private static JsonDocument ParseOne(byte[] bytes)
    {
        Assert.IsTrue(bytes.Length > 1 && bytes[^1] == (byte)'\n');
        Assert.IsFalse(bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }));
        Assert.AreEqual(1, bytes.Count(value => value == (byte)'\n'));
        var json = JsonDocument.Parse(bytes);
        Assert.AreEqual(1, json.RootElement.GetProperty("protocol").GetInt32());
        Assert.IsFalse(Encoding.UTF8.GetString(bytes).Contains("Synthetic closure failure", StringComparison.Ordinal));
        return json;
    }
}
