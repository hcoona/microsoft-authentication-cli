// Inert actual-account adapter. No private inputs or artifact identities are configured.
#nullable enable
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
namespace ConfidentialNativeCaller;

internal static class AdmissionCatalog
{
    private static ActualAdmission? current;
    internal static string[] Slots(Group group) => group == Group.R5Pair ? ["R5a", "R5b"] : [group.ToString()];
    internal static int RunRole(string[] args, long entry, bool worker)
    {
        PrivateRequest.Require(current is null && OperatingSystem.IsWindows() && Stopwatch.IsHighResolution &&
            args.Length == 8 && args[0] == (worker ? "--worker" : "--supervisor") &&
            Enum.TryParse(args[1], false, out Group group) && group.ToString() == args[1] && ExactJson.Nonce(args[2]));
        group = Enum.Parse<Group>(args[1], false);
        long batchEnd = Ticks(args[5]), workEnd = Ticks(args[6]), finalEnd = Ticks(args[7]);
        using var admission = new ActualAdmission(args[3], args[4], group, args[2], batchEnd, workEnd, finalEnd, entry, worker);
        current = admission;
        try
        {
            PublicPlan plan = LoadPublicPlan(group, args[2]);
            Program.ValidatePublicPlan(plan);
            using IDisposable lease = HoldAcceptedInputs(plan, group, args[2], worker);
            return worker ? Program.Work(plan, group, workEnd, false) :
                Program.Supervise(plan, group, args[2], entry, false, null, workEnd, finalEnd);
        }
        finally { current = null; }
    }
    private static long Ticks(string text)
    {
        PrivateRequest.Require(long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long result) && result > 0);
        return result;
    }
    private static ActualAdmission Current => current ?? throw new SafeFailure(Fault.Admission);
    internal static PublicPlan LoadPublicPlan(Group group, string nonce) => Current.Plan(group, nonce);
    internal static IDisposable HoldAcceptedInputs(PublicPlan plan, Group group, string nonce, bool worker) => Current.HoldRole(plan, group, nonce, worker);
    internal static PrivateRequest[] LoadPrivateRequests(Group group) => Current.PrivateRows(group);
    internal static string[] WorkerArguments(Group group, string nonce, long workEnd, long finalEnd) => Current.WorkerArguments(group, nonce, workEnd, finalEnd);
    internal static IDisposable BindWorker(Group group, string nonce, Child child, long workEnd, long finalEnd) => Current.BindWorker(group, nonce, child, workEnd, finalEnd);
}

internal sealed class ActualAdmission : IDisposable
{
    internal const string Root = @"C:\Temp\azureauth-windows-slice-108\confidential-native-account-v1";
    private readonly FixtureNativePins pins;
    private readonly string path, sha, nonce, role, receiptRoot, privatePath;
    private readonly Group group;
    private readonly long batchEnd, workEnd, finalEnd, entry;
    private readonly FixtureFileIdentity privateIdentity;
    private readonly long privateLength;
    private readonly PublicPlan plan;
    private bool roleHeld, privateRead, workerBound, disposed;

    internal ActualAdmission(string path, string sha, Group group, string nonce, long batchEnd,
        long workEnd, long finalEnd, long entry, bool worker)
    {
        this.path = path; this.sha = sha; this.group = group; this.nonce = nonce;
        this.batchEnd = batchEnd; this.workEnd = workEnd; this.finalEnd = finalEnd; this.entry = entry;
        role = worker ? "worker" : "supervisor";
        PrivateRequest.Require(path == Root + @"\control\" + group + "-" + nonce + ".json" && ExactJson.Hash(sha) &&
            workEnd > Stopwatch.GetTimestamp() && workEnd <= CallerRules.Add(entry, 135000, Stopwatch.Frequency) &&
            finalEnd > workEnd && finalEnd <= CallerRules.Add(workEnd, 10000, Stopwatch.Frequency) && finalEnd <= batchEnd);
        OrdinaryEnvironment(workEnd);
        pins = new FixtureNativePins(Before);
        try
        {
            FixtureHeldFile control = pins.Pin(path, sha, -1, 262144);
            using JsonDocument document = JsonDocument.Parse(pins.Read(control, 262144), new JsonDocumentOptions { MaxDepth = 8 });
            JsonElement data = document.RootElement;
            ExactJson.Members(data, "schema", "admitted", "accountEffectsAccepted", "group", "nonce", "protocolSha256",
                "riskDecisionSha256", "sourceAcceptanceSha256", "closureAcceptanceSha256", "batchStartTicks", "batchEndTicks",
                "stopwatchFrequency", "callerPins", "productPins", "productImage", "privateInput", "effects", "environmentMode");
            PrivateRequest.Require(ExactJson.Text(data, "schema") == "confidential-native-account-admission-v1" &&
                ExactJson.Flag(data, "admitted") && ExactJson.Flag(data, "accountEffectsAccepted") &&
                ExactJson.Text(data, "environmentMode") == "constructed-current-user-profile-v1" &&
                ExactJson.Text(data, "group") == group.ToString() && ExactJson.Text(data, "nonce") == nonce &&
                data.GetProperty("stopwatchFrequency").GetInt64() == Stopwatch.Frequency && data.GetProperty("batchEndTicks").GetInt64() == batchEnd);
            long batchStart = data.GetProperty("batchStartTicks").GetInt64();
            PrivateRequest.Require(batchStart > 0 && batchStart <= entry && batchEnd == CallerRules.Add(batchStart, 1800000, Stopwatch.Frequency));
            foreach (string key in new[] { "protocolSha256", "riskDecisionSha256", "sourceAcceptanceSha256", "closureAcceptanceSha256" })
                PrivateRequest.Require(ExactJson.Hash(ExactJson.Text(data, key)));
            JsonElement effects = data.GetProperty("effects");
            ExactJson.Members(effects, "productLaunches", "callerProcesses", "exemptOuterPowerShellCount", "etwAttempts");
            PrivateRequest.Require(effects.GetProperty("productLaunches").GetInt32() == AdmissionCatalog.Slots(group).Length &&
                effects.GetProperty("callerProcesses").GetInt32() == 2 && effects.GetProperty("exemptOuterPowerShellCount").GetInt32() == 1 &&
                effects.GetProperty("etwAttempts").GetInt32() == 0);
            Dictionary<string, FixtureCatalogEntry> expected = FixtureInputCatalog.Required();
            foreach (string key in expected.Keys.Where(key => key.StartsWith(@"artifact\", StringComparison.Ordinal) &&
                !key.StartsWith(@"artifact\NativeCaller.", StringComparison.Ordinal)).ToArray()) expected.Remove(key);
            PrivateRequest.Require(expected.Count == 194);
            JsonElement callers = data.GetProperty("callerPins");
            PrivateRequest.Require(callers.ValueKind == JsonValueKind.Array && callers.GetArrayLength() == 194);
            string? callerHash = null; long total = 0;
            foreach (JsonElement item in callers.EnumerateArray())
            {
                ExactJson.Members(item, "relative", "bytes", "sha256", "identity");
                string relative = ExactJson.Text(item, "relative"), hash = ExactJson.Text(item, "sha256");
                long length = item.GetProperty("bytes").GetInt64();
                PrivateRequest.Require(expected.Remove(relative, out FixtureCatalogEntry? exact) && ExactJson.Hash(hash) &&
                    length > 0 && length <= exact!.MaximumBytes && (exact.Bytes < 0 || length == exact.Bytes) &&
                    (exact.Sha256 is null || hash == exact.Sha256));
                total = checked(total + length); PrivateRequest.Require(total <= 100663296);
                pins.Pin(Root + "\\" + relative, hash, length, exact.MaximumBytes, ExactJson.Identity(item.GetProperty("identity"), length));
                if (relative == @"artifact\NativeCaller.exe") callerHash = hash;
            }
            PrivateRequest.Require(expected.Count == 0 && callerHash is not null);
            string productImage = ExactJson.Text(data, "productImage");
            JsonElement products = data.GetProperty("productPins");
            PrivateRequest.Require(products.ValueKind == JsonValueKind.Array && products.GetArrayLength() is >= 1 and <= 32);
            var productPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase); string? productHash = null;
            foreach (JsonElement item in products.EnumerateArray())
            {
                ExactJson.Members(item, "relative", "bytes", "sha256", "identity");
                string relative = ExactJson.Text(item, "relative"), hash = ExactJson.Text(item, "sha256");
                long length = item.GetProperty("bytes").GetInt64();
                PrivateRequest.Require(relative.StartsWith(@"product\", StringComparison.Ordinal) && productPaths.Add(relative) &&
                    ExactJson.Hash(hash) && length > 0 && length <= 67108864);
                total = checked(total + length); PrivateRequest.Require(total <= 268435456);
                string productPath = Root + "\\" + relative;
                pins.Pin(productPath, hash, length, 67108864, ExactJson.Identity(item.GetProperty("identity"), length));
                if (relative == productImage) productHash = hash;
            }
            PrivateRequest.Require(productHash is not null && productImage.EndsWith(".exe", StringComparison.Ordinal));
            JsonElement privateInput = data.GetProperty("privateInput");
            ExactJson.Members(privateInput, "relative", "bytes", "identity");
            PrivateRequest.Require(ExactJson.Text(privateInput, "relative") == @"private\" + group + ".json");
            privateLength = privateInput.GetProperty("bytes").GetInt64();
            PrivateRequest.Require(privateLength is > 0 and <= 262144);
            privateIdentity = ExactJson.Identity(privateInput.GetProperty("identity"), privateLength);
            privatePath = Root + @"\private\" + group + ".json";
            receiptRoot = Root + @"\records\" + group + "-" + nonce;
            pins.HoldDirectory(receiptRoot);
            plan = new PublicPlan { SelfImage = Root + @"\artifact\NativeCaller.exe", ProductImage = Root + "\\" + productImage,
                WorkingDirectory = Root, ReceiptDirectory = receiptRoot, CallerSha256 = callerHash!, ProductSha256 = productHash!,
                ProtocolSha256 = ExactJson.Text(data, "protocolSha256") };
            Before();
        }
        catch { pins.Dispose(); throw; }
    }

    private void Before() { PrivateRequest.Require(!disposed); CallerRules.Before(Stopwatch.GetTimestamp(), workEnd); }
    internal PublicPlan Plan(Group selected, string selectedNonce)
    { Before(); PrivateRequest.Require(selected == group && selectedNonce == nonce); return plan; }
    internal IDisposable HoldRole(PublicPlan selectedPlan, Group selected, string selectedNonce, bool worker)
    {
        Before(); PrivateRequest.Require(!roleHeld && ReferenceEquals(selectedPlan, Plan(selected, selectedNonce)) &&
            role == (worker ? "worker" : "supervisor") && string.Equals(Environment.ProcessPath, plan.SelfImage, StringComparison.OrdinalIgnoreCase));
        string identityPath = receiptRoot + "\\" + role + "-identity.json";
        if (!worker)
        {
            // The trusted normal controller retains the original Process.Start handle.
            // No private input is opened while waiting for its single atomic handshake.
            long handshakeEnd = Math.Min(workEnd, CallerRules.Add(entry, 2000, Stopwatch.Frequency));
            for (int attempt = 0; !File.Exists(identityPath); attempt++)
            { PrivateRequest.Require(attempt < 200); CallerRules.Before(Stopwatch.GetTimestamp(), handshakeEnd); Thread.Sleep(10); }
        }
        FixtureHeldFile identityFile = pins.Pin(identityPath, null, -1, 4096);
        using JsonDocument identityDocument = JsonDocument.Parse(pins.Read(identityFile, 4096), new JsonDocumentOptions { MaxDepth = 3 });
        JsonElement identity = identityDocument.RootElement;
        ExactJson.Members(identity, "schema", "group", "role", "nonce", "admissionSha256", "pid", "createdFileTime",
            "batchEndTicks", "workEndTicks", "finalEndTicks", "noExperimentLive");
        PrivateRequest.Require(ExactJson.Text(identity, "schema") == "confidential-native-created-role-v1" &&
            ExactJson.Text(identity, "group") == group.ToString() && ExactJson.Text(identity, "role") == role &&
            ExactJson.Text(identity, "nonce") == nonce && ExactJson.Text(identity, "admissionSha256") == sha &&
            identity.GetProperty("batchEndTicks").GetInt64() == batchEnd && identity.GetProperty("workEndTicks").GetInt64() == workEnd &&
            identity.GetProperty("finalEndTicks").GetInt64() == finalEnd && !ExactJson.Flag(identity, "noExperimentLive"));
        FixtureNativePins.CurrentIdentity(identity.GetProperty("pid").GetUInt32(), identity.GetProperty("createdFileTime").GetInt64());
        if (worker) FixtureNativePins.RequireCurrentJob("Local\\azureauth-confidential-108-" + group + "-" + nonce);
        roleHeld = true; Before(); return this;
    }
    internal PrivateRequest[] PrivateRows(Group selected)
    {
        Before(); PrivateRequest.Require(roleHeld && role == "worker" && group == selected && !privateRead);
        privateRead = true;
        FixtureHeldFile file = pins.Pin(privatePath, null, privateLength, 262144, privateIdentity);
        byte[] bytes = pins.Read(file, 262144);
        try { PrivateRequest[] rows = PrivateRequestDocument.Parse(bytes, group); Before(); return rows; }
        finally { Array.Clear(bytes); }
    }
    internal string[] WorkerArguments(Group selected, string selectedNonce, long selectedWorkEnd, long selectedFinalEnd)
    {
        Before(); PrivateRequest.Require(roleHeld && role == "supervisor" && selected == group && selectedNonce == nonce &&
            selectedWorkEnd == workEnd && selectedFinalEnd == finalEnd);
        return ["--worker", group.ToString(), nonce, path, sha, batchEnd.ToString(CultureInfo.InvariantCulture),
            workEnd.ToString(CultureInfo.InvariantCulture), finalEnd.ToString(CultureInfo.InvariantCulture)];
    }
    internal IDisposable BindWorker(Group selected, string selectedNonce, Child child, long selectedWorkEnd, long selectedFinalEnd)
    {
        _ = WorkerArguments(selected, selectedNonce, selectedWorkEnd, selectedFinalEnd);
        PrivateRequest.Require(!workerBound && !child.Exited() && child.ProcessId > 0 && child.CreatedFileTime > 0);
        workerBound = true;
        byte[] record = JsonSerializer.SerializeToUtf8Bytes(new { schema = "confidential-native-created-role-v1",
            group = group.ToString(), role = "worker", nonce, admissionSha256 = sha, pid = child.ProcessId,
            createdFileTime = child.CreatedFileTime, batchEndTicks = batchEnd, workEndTicks = workEnd,
            finalEndTicks = finalEnd, noExperimentLive = false });
        return pins.CreatePinnedRecord(receiptRoot + @"\worker-identity.json", record, Before);
    }
    private static void OrdinaryEnvironment(long workEnd)
    {
        int entries = 0;
        foreach (DictionaryEntry item in Environment.GetEnvironmentVariables())
        {
            CallerRules.Before(Stopwatch.GetTimestamp(), workEnd);
            PrivateRequest.Require(++entries <= CurrentUserEnvironment.MaximumEntries &&
                !CurrentUserEnvironment.RejectsRuntimeKey((string)item.Key));
        }
    }
    public void Dispose() { if (disposed) return; disposed = true; pins.Dispose(); }
}
