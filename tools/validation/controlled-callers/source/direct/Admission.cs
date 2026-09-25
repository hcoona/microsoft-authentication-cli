// Inert source proposal. Concrete adapters do not activate source or supply accepted runtime bindings.
#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ConfidentialWsl;

internal enum Slot { R2, R3, R4, R9, R10, D0, D1, D2 }
internal static class DirectRoles
{
    internal static bool Close(Slot slot) => slot is Slot.R9 or Slot.D2;
    internal static bool Fixture(Slot slot) => slot is Slot.D1 or Slot.D2;
}
internal enum Fault { None, Unconfigured, Admission, Native, Capture, Deadline, Protocol, Expectation, Trace, Identity, Lifetime }
internal sealed class SafeFailure(Fault fault) : Exception
{
    internal Fault Fault { get; } = fault;
    public override string ToString() => nameof(SafeFailure);
}
internal sealed class PublicPlan
{
    internal required string ObserverImage { get; init; }
    internal required string ProductImage { get; init; }
    internal required string WorkingDirectory { get; init; }
    internal required string RecordDirectory { get; init; }
    internal required string ProductSha256 { get; init; }
    internal required string CallerSha256 { get; init; }
    internal required string ProtocolSha256 { get; init; }
    internal string? NativeBaselineSha256 { get; init; }
    internal int ExpectedExit { get; init; }
    internal int ProductTimeoutSeconds { get; init; }
}
internal sealed class PrivateExpectation
{
    // Loaded independently from the same already-selected private role references.
    // Never serialize/hash/format this object, its arguments or its command.
    internal required string[] Arguments { get; init; }
    internal bool SoleLaunchIdentityPremiseAccepted { get; init; }
    internal bool TargetedStopPremiseAccepted { get; init; }
    internal string Command(PublicPlan plan)
    {
        Check(Arguments.Length is >= 16 and <= 160);
        foreach (string value in Arguments) Check(DirectToken(value));
        string command = plan.ProductImage + " " + string.Join(" ", Arguments);
        Check(command.Length <= 32766 && SoleLaunchIdentityPremiseAccepted);
        return command;
    }
    internal static bool DirectToken(string value) => value.Length > 0 &&
        value.All(c => c is >= (char)33 and <= (char)126 && c != '\"' && c != '\'');
    internal static void Check(bool condition)
    { if (!condition) throw new SafeFailure(Fault.Admission); }
    public override string ToString() => nameof(PrivateExpectation);
}
internal static class AdmissionCatalog
{
    private static AcceptedDirectInputs? current;
    private static AcceptedDirectInputs Current => current ?? throw new SafeFailure(Fault.Unconfigured);
    internal static void Configure(string path,string sha,Slot slot,string nonce,bool worker,long workEnd,string? parentBaseline)
    {
        PrivateExpectation.Check(current is null);
        current=new AcceptedDirectInputs(path,sha,slot,nonce,worker,workEnd,parentBaseline);
    }
    internal static PublicPlan LoadPublicPlan(Slot slot,string nonce)=>Current.Plan;
    internal static IDisposable HoldAcceptedInputs(PublicPlan plan,Slot slot,string nonce,bool worker)
        => Current.Hold(plan,slot,nonce,worker);
    internal static PrivateExpectation LoadPrivateExpectation(Slot slot)=>Current.Request(slot);
    internal static void RequireCalibrationAdmission(PublicPlan plan,string nonce)=>Current.Calibration(plan,nonce);
    internal static string[] WorkerArguments(Slot slot,string nonce,long workEnd)=>Current.WorkerArguments(slot,nonce,workEnd);
    internal static void Close(){current?.Dispose();}

    internal static void Validate(PublicPlan plan)
    {
        foreach (string value in new[] { plan.ProductSha256, plan.CallerSha256, plan.ProtocolSha256 })
            PrivateExpectation.Check(Regex.IsMatch(value, "\\A[0-9a-f]{64}\\z"));
        foreach (string value in new[] { plan.ObserverImage, plan.ProductImage, plan.WorkingDirectory, plan.RecordDirectory })
            PrivateExpectation.Check(value.StartsWith(@"C:\", StringComparison.Ordinal) &&
                value.Length <= 1024 && PrivateExpectation.DirectToken(value));
        PrivateExpectation.Check(plan.ExpectedExit is 0 or 1 && plan.ProductTimeoutSeconds is >= 1 and <= 120);
    }
}
internal static class PublicRecords
{
    // The held admission lease must establish exclusive directory ownership, no reparse
    // components/replacement and this filesystem's cross-WSL publication semantics.
    internal static string PathOf(PublicPlan plan, string name) => Path.Combine(plan.RecordDirectory, name);
    internal static Dictionary<string, object> Identity(PublicPlan plan, Slot slot, string nonce, string kind)
    {
        var result=new Dictionary<string,object> {
            ["schema"] = "direct-wsl-2", ["kind"] = kind, ["slot"] = slot.ToString(), ["nonce"] = nonce,
            ["productImage"] = plan.ProductImage, ["productSha256"] = plan.ProductSha256,
            ["callerSha256"] = plan.CallerSha256, ["protocolSha256"] = plan.ProtocolSha256,
            ["expectedExit"] = plan.ExpectedExit, ["productTimeoutSeconds"] = plan.ProductTimeoutSeconds,
        };
        if(plan.NativeBaselineSha256 is not null)result["nativeBaselineSha256"]=plan.NativeBaselineSha256;
        return result;
    }
    internal static void Publish(PublicPlan plan, string name, Dictionary<string, object> record)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(record);
        PrivateExpectation.Check(bytes.Length is > 0 and <= 4096);
        string final = PathOf(plan, name), temporary = final + ".pending";
        using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { stream.Write(bytes); stream.Flush(true); }
        // Never overwrite, retry, append or publish a fallback record after a write failure.
        File.Move(temporary, final, false);
    }
    internal static void RequireIntent(PublicPlan plan, Slot slot, string nonce)
    {
        using var stream = new FileStream(PathOf(plan, "intent.json"), FileMode.Open, FileAccess.Read, FileShare.Read);
        PrivateExpectation.Check(stream.Length is > 0 and <= 4096);
        byte[] bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        PrivateExpectation.Check(stream.ReadByte() == -1);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
        Dictionary<string, object> expected = Identity(plan, slot, nonce, "intent");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        PrivateExpectation.Check(document.RootElement.ValueKind == JsonValueKind.Object);
        foreach (JsonProperty field in document.RootElement.EnumerateObject())
        {
            PrivateExpectation.Check(seen.Add(field.Name) && expected.TryGetValue(field.Name, out _));
            object value = expected[field.Name];
            PrivateExpectation.Check(value is string text ?
                field.Value.ValueKind == JsonValueKind.String && field.Value.GetString() == text :
                field.Value.ValueKind == JsonValueKind.Number && field.Value.TryGetInt32(out int n) && n == (int)value);
        }
        PrivateExpectation.Check(seen.Count == expected.Count);
    }
    internal static bool StopRequested(PublicPlan plan)
    {
        string path = PathOf(plan, "stop");
        if (!File.Exists(path)) return false;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        PrivateExpectation.Check(stream.Length == 0); return true;
    }
}
