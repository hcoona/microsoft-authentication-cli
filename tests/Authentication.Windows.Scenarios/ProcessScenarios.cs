using System.Text;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Windows.Scenarios;

[TestClass]
[DoNotParallelize]
public sealed class ProcessScenarios
{
    [TestMethod]
    public async Task RootHelpCompletesWithoutAuthentication()
    {
        using var child = new ProcessFixture("help");
        await child.FinishAsync();
        AssertNormalExit(child, 0);
        var text = Encoding.UTF8.GetString(child.Output);
        StringAssert.Contains(text, "authenticate");
        StringAssert.Contains(text, "--profile");
        Assert.IsFalse(text.Contains("SYNTHETIC_INVALID_VERSION", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task MalformedAuthenticationReturnsTheBootstrapFailure()
    {
        using var child = new ProcessFixture("malformed");
        await child.FinishAsync();
        AssertFailure(child, "invalid_request");
        Assert.IsFalse(Encoding.UTF8.GetString(child.Output).Contains("SYNTHETIC_INVALID_VERSION", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task SelectedRequestReturnsOneSuccessDespiteBrokenDiagnostics()
    {
        using var child = new ProcessFixture("success");
        await child.FinishAsync();
        AssertNormalExit(child, 0);
        AssertSuccessBytes(child);
        Assert.IsTrue(child.Marked("candidate-returned"));
        Assert.AreEqual(0, child.Error.Length);
    }

    [TestMethod]
    public async Task FlaggedRegularFileStopsBeforeProfileAndProvider()
    {
        using var child = new ProcessFixture("file-stdin");
        await child.FinishAsync();
        AssertFailure(child, "invalid_request");
        AssertNoAdmissionEffects(child);
    }

    [TestMethod]
    public async Task AlreadyClosedLifetimePipeCancelsBeforeAuthentication()
    {
        using var child = new ProcessFixture("closed-stdin");
        await child.FinishAsync();
        AssertFailure(child, "cancelled");
        AssertNoAdmissionEffects(child);
    }

    [TestMethod]
    public async Task WriterClosureRejectsLateSuccessAndEndsTheProcess()
    {
        using var child = new ProcessFixture("close-pending");
        await RequireMarkerAsync(child, "provider-ready");
        child.CloseInput();
        await child.FinishAsync();
        AssertFailure(child, "cancelled");
        Assert.IsTrue(child.Marked("cancel-observed"));
        Assert.IsTrue(child.Marked("candidate-returned"));
        AssertExitInterval(child, child.WriterCloseBefore, 1);
    }

    [TestMethod]
    public async Task ClosedStdinWithoutTheFlagDoesNotCancel()
    {
        using var child = new ProcessFixture("unused-stdin");
        await child.FinishAsync();
        AssertNormalExit(child, 0);
        AssertSuccessBytes(child);
    }

    [TestMethod]
    public async Task LifetimePipePayloadIsIgnoredAndClosureStillCancels()
    {
        using var child = new ProcessFixture("data-close");
        await RequireMarkerAsync(child, "provider-ready");
        child.CloseInput(payload: true);
        await child.FinishAsync();
        AssertFailure(child, "cancelled");
        Assert.IsTrue(child.Marked("cancel-observed"));
        AssertExitInterval(child, child.WriterCloseBefore, 1);
        Assert.IsFalse(Encoding.UTF8.GetString(child.Output.Concat(child.Error).ToArray())
            .Contains("SYNTHETIC_IGNORED_STDIN_DATA", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task DeadlineEndsUncooperativeWorkWithinTheProcessBound()
    {
        using var child = new ProcessFixture("deadline");
        await RequireMarkerAsync(child, "provider-ready");
        await child.FinishAsync();
        Assert.IsFalse(child.Forced, "The product must end before fixture enforcement.");
        AssertExitInterval(child, child.EntryTimestamp, 2);
        Assert.AreEqual(2u, child.ExitCode, "Forced product shutdown is a transport failure.");
        Assert.IsTrue(child.Marked("callback-pending"));
        Assert.IsFalse(child.Marked("candidate-returned"));
        if (child.Output.Length > 0)
        {
            using var json = ParseOne(child.Output);
            Assert.AreEqual("timeout", json.RootElement.GetProperty("outcome").GetString());
            Assert.IsFalse(json.RootElement.TryGetProperty("accessToken", out _));
        }
    }

    [TestMethod]
    public async Task BrokenResultReaderEndsWithTransportFailure()
    {
        using var child = new ProcessFixture("broken-output");
        await child.FinishAsync();
        Assert.IsFalse(child.Forced);
        Assert.IsTrue(child.Marked("candidate-returned"));
        Assert.AreEqual(0, child.Output.Length);
        Assert.AreEqual(2u, child.ExitCode);
    }

    [TestMethod]
    public async Task UndrainedResultPipeCannotKeepTheProcessAlive()
    {
        using var child = new ProcessFixture("blocked-output");
        await RequireMarkerAsync(child, "candidate-returned");
        Assert.IsTrue(await child.ObserveBufferedOutputAsync(), "Observe actual result bytes before claiming a blocked write.");
        await child.FinishAsync();
        Assert.IsFalse(child.Forced, "The product must end before fixture enforcement.");
        Assert.AreEqual(2u, child.ExitCode);
        AssertExitInterval(child, child.EntryTimestamp, 2);
        Assert.IsTrue(child.Output.Length < 262144);
        Assert.IsFalse(child.Output.AsSpan().EndsWith("}\n"u8));
    }

    [TestMethod]
    public async Task BlockedDiagnosticsDoNotChangeTheAuthenticationResultOrKeepTheProcessAlive()
    {
        using var child = new ProcessFixture("blocked-diagnostics");
        await child.FinishAsync();
        Assert.IsFalse(child.Forced);
        AssertExitInterval(child, child.EntryTimestamp, 2);
        AssertSuccessBytes(child);
        Assert.AreEqual(0u, child.ExitCode, "Diagnostic loss must preserve successful process status.");
        Assert.IsTrue(child.DiagnosticPrefill > 0);
        Assert.IsTrue(child.Error.Length <= child.DiagnosticPrefill + 8192);
    }

    private static async Task RequireMarkerAsync(ProcessFixture child, string name)
    {
        var observed = await child.WaitForMarkerAsync(name);
        Assert.IsTrue(child.Marked("entered"), "The controlled child must enter before a business red is accepted.");
        Assert.IsTrue(observed, "The controlled request must reach its required scenario state.");
    }

    private static void AssertExitInterval(ProcessFixture child, long start, int seconds)
    {
        // Same-host Windows QPC underlies TimeProvider.System in both processes.
        // The fixed 100 ms observation tolerance includes 10 ms polling and
        // scheduling uncertainty; it does not enlarge the product's allowance.
        Assert.IsTrue(start > 0 && child.ExitObservedTimestamp >= start);
        var interval = TimeProvider.System.GetElapsedTime(start, child.ExitObservedTimestamp);
        Assert.IsTrue(interval <= TimeSpan.FromSeconds(seconds) + TimeSpan.FromMilliseconds(100),
            "The observed product interval exceeded its admitted measurement tolerance.");
    }

    private static void AssertNoAdmissionEffects(ProcessFixture child)
    {
        Assert.IsTrue(child.Marked("entered"));
        Assert.IsFalse(child.Marked("profile-read"));
        Assert.IsFalse(child.Marked("provider-created"));
    }

    private static void AssertNormalExit(ProcessFixture child, uint expected)
    {
        Assert.IsFalse(child.Forced);
        Assert.AreEqual(expected, child.ExitCode);
    }

    private static void AssertFailure(ProcessFixture child, string outcome)
    {
        AssertNormalExit(child, 1);
        using var json = ParseOne(child.Output);
        Assert.AreEqual(outcome, json.RootElement.GetProperty("outcome").GetString());
        Assert.AreEqual(outcome, json.RootElement.GetProperty("reason").GetString());
        CollectionAssert.AreEquivalent(new[] { "protocol", "outcome", "reason" },
            json.RootElement.EnumerateObject().Select(property => property.Name).ToArray());
    }

    private static void AssertSuccessBytes(ProcessFixture child)
    {
        using var json = ParseOne(child.Output);
        var result = json.RootElement;
        Assert.AreEqual("success", result.GetProperty("outcome").GetString());
        Assert.AreEqual(ProcessChild.Email, result.GetProperty("accountEmail").GetString());
        Assert.AreEqual(ProcessChild.Token, result.GetProperty("accessToken").GetString());
        Assert.AreEqual(ProcessChild.Tenant, result.GetProperty("tenantId").GetString());
        Assert.AreEqual("Bearer", result.GetProperty("tokenType").GetString());
        Assert.AreEqual("silent", result.GetProperty("interaction").GetString());
        CollectionAssert.AreEqual(new[] { ProcessChild.Scope },
            result.GetProperty("scopes").EnumerateArray().Select(value => value.GetString()).ToArray());
        CollectionAssert.AreEquivalent(new[] { "protocol", "outcome", "accessToken", "tokenType", "expiresOn",
            "accountEmail", "tenantId", "authority", "scopes", "mechanism", "interaction", "warnings" },
            result.EnumerateObject().Select(property => property.Name).ToArray());
    }

    private static JsonDocument ParseOne(byte[] bytes)
    {
        Assert.IsTrue(bytes.Length > 1 && bytes[^1] == (byte)'\n');
        Assert.IsFalse(bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }));
        Assert.AreEqual(1, bytes.Count(value => value == (byte)'\n'));
        var json = JsonDocument.Parse(bytes);
        Assert.AreEqual(1, json.RootElement.GetProperty("protocol").GetInt32());
        return json;
    }
}
