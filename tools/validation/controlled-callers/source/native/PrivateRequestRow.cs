// Shared local-only row structure. Never serialize, log, hash, or retain parsed rows.
#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace ConfidentialInputs;

internal sealed class PrivateRequestRow
{
    internal required string ProfilePath { get; init; }
    internal required string TenantArgument { get; init; }
    internal Guid? ExactResultTenant { get; init; }
    internal required string AccountEmail { get; init; }
    internal required string[] Scopes { get; init; }
    internal bool InteractionAllowed { get; init; }
    internal int TimeoutSeconds { get; init; }
    internal required string Outcome { get; init; }
    internal string? RequiredInteraction { get; init; }
    internal bool LifetimePipe { get; init; }
    internal int? CloseAfterMs { get; init; }
    internal bool RequireCloseAfterLiveSample { get; init; }
    internal bool RequirePersistenceUnconfirmed { get; init; }
    internal bool DefaultAssociationIndependentlyAccepted { get; init; }
    public override string ToString() => nameof(PrivateRequestRow);

    internal static PrivateRequestRow Parse(JsonElement row)
    {
        string[] fields = ["profilePath", "tenantArgument", "exactResultTenant", "accountEmail", "scopes",
            "interactionAllowed", "timeoutSeconds", "outcome", "requiredInteraction", "lifetimePipe",
            "closeAfterMs", "requireCloseAfterLiveSample", "requirePersistenceUnconfirmed",
            "defaultAssociationIndependentlyAccepted"];
        Require(row.ValueKind == JsonValueKind.Object);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty field in row.EnumerateObject())
            Require(seen.Add(field.Name) && fields.Contains(field.Name, StringComparer.Ordinal));
        Require(seen.Count == fields.Length);
        JsonElement scopes = row.GetProperty("scopes");
        Require(scopes.ValueKind == JsonValueKind.Array && scopes.GetArrayLength() is >= 1 and <= 64);
        string[] scopeValues = scopes.EnumerateArray().Select(value =>
        {
            Require(value.ValueKind == JsonValueKind.String);
            string text = value.GetString()!;
            Require(text.Length is >= 1 and <= 2048);
            return text;
        }).ToArray();
        JsonElement tenant = row.GetProperty("exactResultTenant");
        Guid? exactTenant = null;
        if (tenant.ValueKind != JsonValueKind.Null)
        {
            Require(tenant.ValueKind == JsonValueKind.String && ExactGuid(tenant.GetString()!, out _));
            exactTenant = Guid.ParseExact(tenant.GetString()!, "D");
            Require(exactTenant != Guid.Empty);
        }
        string tenantArgument = Text(row, "tenantArgument");
        Require(tenantArgument == "common" ||
            (ExactGuid(tenantArgument, out Guid explicitTenant) && explicitTenant != Guid.Empty && exactTenant == explicitTenant));
        string outcome = Text(row, "outcome");
        Require(outcome is "success" or "invalid_request" or "interaction_required" or "account_ambiguous" or
            "identity_validation_failed" or "cancelled" or "denied" or "mechanism_unavailable" or
            "temporarily_unavailable" or "timeout" or "internal_failure");
        JsonElement interaction = row.GetProperty("requiredInteraction"), close = row.GetProperty("closeAfterMs");
        string? requiredInteraction = interaction.ValueKind == JsonValueKind.Null ? null : Text(row, "requiredInteraction");
        Require(requiredInteraction is null or "silent" or "interactive");
        Require(row.GetProperty("timeoutSeconds").TryGetInt32(out int seconds) && seconds is >= 1 and <= 120);
        int? closeAfter = null;
        if (close.ValueKind != JsonValueKind.Null)
        {
            Require(close.TryGetInt32(out int milliseconds) && milliseconds >= 0 && milliseconds < seconds * 1000);
            closeAfter = milliseconds;
        }
        bool allowed = Flag(row, "interactionAllowed"), lifetime = Flag(row, "lifetimePipe");
        bool afterLive = Flag(row, "requireCloseAfterLiveSample");
        Require((requiredInteraction != "interactive" || allowed) && (closeAfter is null || lifetime) &&
            (!afterLive || closeAfter is not null));
        string profile = Text(row, "profilePath"), email = Text(row, "accountEmail");
        Require(profile.Length is >= 3 and <= 32767 && email.Length is >= 3 and <= 640);
        return new PrivateRequestRow
        {
            ProfilePath = profile, TenantArgument = tenantArgument, ExactResultTenant = exactTenant,
            AccountEmail = email, Scopes = scopeValues, InteractionAllowed = allowed, TimeoutSeconds = seconds,
            Outcome = outcome, RequiredInteraction = requiredInteraction, LifetimePipe = lifetime,
            CloseAfterMs = closeAfter, RequireCloseAfterLiveSample = afterLive,
            RequirePersistenceUnconfirmed = Flag(row, "requirePersistenceUnconfirmed"),
            DefaultAssociationIndependentlyAccepted = Flag(row, "defaultAssociationIndependentlyAccepted")
        };
    }

    private static string Text(JsonElement value, string name)
    { JsonElement field = value.GetProperty(name); Require(field.ValueKind == JsonValueKind.String); return field.GetString()!; }
    private static bool Flag(JsonElement value, string name)
    { JsonElement field = value.GetProperty(name); Require(field.ValueKind is JsonValueKind.True or JsonValueKind.False); return field.GetBoolean(); }
    private static bool ExactGuid(string text, out Guid result)
    {
        result = default;
        if (text.Length != 36) return false;
        for (int i = 0; i < text.Length; i++)
        {
            if (i is 8 or 13 or 18 or 23) { if (text[i] != '-') return false; }
            else if (text[i] is not (>= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F')) return false;
        }
        return Guid.TryParseExact(text, "D", out result);
    }
    private static void Require(bool value) { if (!value) throw new InvalidOperationException("Private row refused."); }
}
