// Local-only selector parsing. Do not serialize, hash, log, or retain these rows.
#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
namespace ConfidentialNativeCaller;

internal static class ExactJson
{
    internal static void Members(JsonElement value, params string[] names)
    {
        PrivateRequest.Require(value.ValueKind == JsonValueKind.Object);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty field in value.EnumerateObject())
            PrivateRequest.Require(seen.Add(field.Name) && names.Contains(field.Name, StringComparer.Ordinal));
        PrivateRequest.Require(seen.Count == names.Length);
    }
    internal static string Text(JsonElement value, string name)
    {
        JsonElement field = value.GetProperty(name);
        PrivateRequest.Require(field.ValueKind == JsonValueKind.String);
        return field.GetString()!;
    }
    internal static bool Flag(JsonElement value, string name)
    {
        JsonElement field = value.GetProperty(name);
        PrivateRequest.Require(field.ValueKind is JsonValueKind.True or JsonValueKind.False);
        return field.GetBoolean();
    }
    internal static bool Hash(string value) => value.Length == 64 &&
        value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static bool Nonce(string value) => value.Length == 32 && value[12] == '4' &&
        value[16] is '8' or '9' or 'a' or 'b' && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static FixtureFileIdentity Identity(JsonElement item, long length)
    {
        Members(item, "volume", "index", "attributes", "created", "modified", "changed", "links");
        var identity = new FixtureFileIdentity(item.GetProperty("volume").GetUInt32(),
            item.GetProperty("index").GetUInt64(), item.GetProperty("attributes").GetUInt32(),
            item.GetProperty("created").GetInt64(), item.GetProperty("modified").GetInt64(),
            item.GetProperty("changed").GetInt64(), length, item.GetProperty("links").GetUInt32());
        PrivateRequest.Require(identity.Index > 0 && identity.Created > 0 && identity.Modified > 0 &&
            identity.Changed > 0 && identity.Links == 1 && (identity.Attributes & 0x410) == 0);
        return identity;
    }
}

internal static class PrivateRequestDocument
{
    internal static PrivateRequest[] Parse(byte[] bytes, Group group)
    {
        // Caller owns and clears the source buffer. Managed strings are ephemeral but
        // this does not promise erasure of all runtime or operating-system copies.
        using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 5 });
        JsonElement root = document.RootElement;
        ExactJson.Members(root, "schema", "group", "requests");
        PrivateRequest.Require(ExactJson.Text(root, "schema") == "confidential-native-private-requests-v1" &&
            ExactJson.Text(root, "group") == group.ToString());
        JsonElement rows = root.GetProperty("requests");
        PrivateRequest.Require(rows.ValueKind == JsonValueKind.Array &&
            rows.GetArrayLength() == AdmissionCatalog.Slots(group).Length);
        return rows.EnumerateArray().Select(ParseRow).ToArray();
    }

    internal static PrivateRequest ParseRow(JsonElement row)
    {
        ConfidentialInputs.PrivateRequestRow shared = ConfidentialInputs.PrivateRequestRow.Parse(row);
        var request = new PrivateRequest
        {
            ProfilePath = shared.ProfilePath, TenantArgument = shared.TenantArgument,
            ExactResultTenant = shared.ExactResultTenant, Email = shared.AccountEmail, Scopes = shared.Scopes,
            InteractionAllowed = shared.InteractionAllowed, TimeoutSeconds = shared.TimeoutSeconds,
            LifetimePipe = shared.LifetimePipe, CloseWriterAfterMilliseconds = shared.CloseAfterMs,
            RequireCloseAfterLiveSample = shared.RequireCloseAfterLiveSample,
            RequirePersistenceUnconfirmed = shared.RequirePersistenceUnconfirmed,
            DefaultAssociationIndependentlyAccepted = shared.DefaultAssociationIndependentlyAccepted,
            ExpectedRoute = shared.RequiredInteraction switch
            { null => Route.None, "silent" => Route.Silent, "interactive" => Route.Interactive, _ => throw new SafeFailure(Fault.Admission) },
            ExpectedOutcome = shared.Outcome switch
            {
                "success" => Outcome.Success, "invalid_request" => Outcome.InvalidRequest,
                "interaction_required" => Outcome.InteractionRequired, "account_ambiguous" => Outcome.AccountAmbiguous,
                "identity_validation_failed" => Outcome.IdentityValidationFailed, "cancelled" => Outcome.Cancelled,
                "denied" => Outcome.Denied, "mechanism_unavailable" => Outcome.MechanismUnavailable,
                "temporarily_unavailable" => Outcome.TemporarilyUnavailable, "timeout" => Outcome.Timeout,
                "internal_failure" => Outcome.InternalFailure, _ => throw new SafeFailure(Fault.Admission)
            }
        };
        request.Validate();
        return request;
    }
}
