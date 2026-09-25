// Source-only validation proposal. No executable admission or private reference is configured.
#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;

namespace ConfidentialNativeCaller;

internal enum Group { R1, R5Pair, R6, R7, R8, R11 }
internal enum Outcome { Unknown, Success, InvalidRequest, InteractionRequired, AccountAmbiguous,
    IdentityValidationFailed, Cancelled, Denied, MechanismUnavailable, TemporarilyUnavailable, Timeout, InternalFailure }
internal enum Route { None, Silent, Interactive }
internal enum Fault { Unconfigured, Admission, Native, Capture, Deadline, Protocol, Expectation }
internal sealed class SafeFailure(Fault fault) : Exception
{
    internal Fault Fault { get; } = fault;
    public override string ToString() => nameof(SafeFailure);
}

// These are public artifact/control inputs, not authentication selectors.
internal sealed class PublicPlan
{
    internal required string SelfImage { get; init; }
    internal required string ProductImage { get; init; }
    internal required string WorkingDirectory { get; init; }
    internal required string ReceiptDirectory { get; init; }
    internal required string ProductSha256 { get; init; }
    internal required string CallerSha256 { get; init; }
    internal required string ProtocolSha256 { get; init; }
}

// Never serialize, format, hash or put this object into an exception/receipt.
internal sealed class PrivateRequest
{
    internal required string ProfilePath { get; init; }
    internal required string Email { get; init; }
    internal required string[] Scopes { get; init; }
    internal required string TenantArgument { get; init; }
    internal Guid? ExactResultTenant { get; init; }
    internal bool InteractionAllowed { get; init; }
    internal int TimeoutSeconds { get; init; } = 120;
    internal bool LifetimePipe { get; init; }
    internal int? CloseWriterAfterMilliseconds { get; init; }
    internal bool RequireCloseAfterLiveSample { get; init; }
    internal Outcome ExpectedOutcome { get; init; }
    internal Route ExpectedRoute { get; init; }
    internal bool RequirePersistenceUnconfirmed { get; init; }
    // /.default association is source/protocol evidence; the result has no operation ID.
    internal bool DefaultAssociationIndependentlyAccepted { get; init; }
    public override string ToString() => nameof(PrivateRequest);

    internal string[] Arguments()
    {
        var args = new List<string> { "authenticate", "--protocol", "1", "--profile", ProfilePath,
            "--account-email", Email, "--interaction", InteractionAllowed ? "interactive-if-needed" : "non-interactive-only",
            "--tenant", TenantArgument, "--timeout-seconds", TimeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--telemetry", "off" };
        foreach (string scope in Scopes) { args.Add("--scope"); args.Add(scope); }
        if (LifetimePipe) args.Add("--cancel-on-stdin-close");
        return args.ToArray();
    }

    internal void Validate()
    {
        Require(TimeoutSeconds is >= 1 and <= 120 && ExpectedOutcome != Outcome.Unknown);
        Require(ProfilePath.Length is >= 3 and <= 32767 && char.IsAsciiLetter(ProfilePath[0]) &&
            ProfilePath[1] == ':' && ProfilePath[2] == '\\' && !ProfilePath.Any(char.IsControl));
        Require(HasCharacterLength(Email, 3, 320) && Email.IndexOf('@') > 0 &&
            Email.IndexOf('@') == Email.LastIndexOf('@') && !Email.EndsWith('@') &&
            !Email.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)));
        if (TenantArgument != "common")
            Require(TryExactGuid(TenantArgument, out Guid requestedTenant) &&
                requestedTenant != Guid.Empty && ExactResultTenant == requestedTenant);
        Require(ExactResultTenant is null || ExactResultTenant != Guid.Empty);
        Require(Scopes.Length is >= 1 and <= 64 && Scopes.Distinct(StringComparer.Ordinal).Count() == Scopes.Length);
        string? resource = null;
        foreach (string scope in Scopes)
        {
            int split = scope.LastIndexOf('/');
            Require(scope.Length is >= 1 and <= 2048 && split > 0 && split < scope.Length - 1 &&
                !scope.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)));
            string prefix = scope[..split];
            Require(resource is null || resource == prefix);
            Require(TryExactGuid(prefix, out _) ||
                (Uri.TryCreate(prefix, UriKind.Absolute, out Uri? uri) && uri.IsWellFormedOriginalString() &&
                 uri.Authority.Length > 0 && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0 &&
                 !prefix[(prefix.IndexOf("://", StringComparison.Ordinal) + 3)..].Split('/')[0].Contains('@')));
            if (scope.EndsWith("/.default", StringComparison.Ordinal))
                Require(Scopes.Length == 1 && DefaultAssociationIndependentlyAccepted);
            resource = prefix;
        }
        Require(CloseWriterAfterMilliseconds is null ||
            (LifetimePipe && CloseWriterAfterMilliseconds >= 0 && CloseWriterAfterMilliseconds < TimeoutSeconds * 1000));
        Require(!RequireCloseAfterLiveSample || CloseWriterAfterMilliseconds is not null);
        Require(ExpectedRoute != Route.Interactive || InteractionAllowed);
    }
    internal static bool TryExactGuid(string value, out Guid result)
    {
        result = default;
        // TryParseExact trims whitespace; validate the original D-form first.
        if (value.Length != 36) return false;
        for (int i = 0; i < value.Length; i++)
        {
            if (i is 8 or 13 or 18 or 23)
            { if (value[i] != '-') return false; }
            else if (value[i] is not (>= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F'))
                return false;
        }
        return Guid.TryParseExact(value, "D", out result);
    }

    internal static bool HasCharacterLength(string value, int minimum, int maximum)
    {
        int count = 0;
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]))
            { if (++i == value.Length || !char.IsLowSurrogate(value[i])) return false; }
            else if (char.IsLowSurrogate(value[i])) return false;
            if (++count > maximum) return false;
        }
        return count >= minimum;
    }
    internal static void Require(bool value) { if (!value) throw new SafeFailure(Fault.Admission); }
}
