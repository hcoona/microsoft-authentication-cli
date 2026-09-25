// Inert private-row adapter. It reads no file and emits no private value or digest.
#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace ConfidentialWsl;
internal static class DirectRequest
{
    private static readonly string[] Outcomes=["success","invalid_request","interaction_required","account_ambiguous",
        "identity_validation_failed","cancelled","denied","mechanism_unavailable","temporarily_unavailable","timeout","internal_failure"];
    private static void Need(bool value)=>PrivateExpectation.Check(value);
    private static string Text(JsonElement value)
    { Need(value.ValueKind==JsonValueKind.String);return value.GetString()!; }
    private static string Text(JsonElement row,string key)=>Text(row.GetProperty(key));
    private static bool GuidText(string value)=>Regex.IsMatch(value,
        "\\A[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\\z");
    internal static PrivateExpectation FromDocument(ReadOnlyMemory<byte> bytes,PublicPlan plan,Slot slot,string nonce,
        bool soleLaunchAccepted,bool targetedStopAccepted)
    {
        Need(bytes.Length is >0 and <=262144);
        using JsonDocument doc=JsonDocument.Parse(bytes,new JsonDocumentOptions {MaxDepth=8});
        JsonElement data=doc.RootElement;Need(data.ValueKind==JsonValueKind.Object);
        var seen=new HashSet<string>(StringComparer.Ordinal);
        string[] names=["schema","slot","nonce","request"];
        foreach(JsonProperty field in data.EnumerateObject())Need(seen.Add(field.Name) && names.Contains(field.Name,StringComparer.Ordinal));
        Need(seen.Count==names.Length && Text(data,"schema")=="confidential-direct-request-v1" &&
            Text(data,"slot")==slot.ToString() && Text(data,"nonce")==nonce);
        return FromRow(data.GetProperty("request"),plan,slot,soleLaunchAccepted,targetedStopAccepted);
    }
    internal static PrivateExpectation FromRow(JsonElement row, PublicPlan plan, Slot slot,
        bool soleLaunchAccepted, bool targetedStopAccepted)
    {
        Need(slot is Slot.R2 or Slot.R3 or Slot.R4 or Slot.R9 or Slot.R10);
        ConfidentialInputs.PrivateRequestRow parsed=ConfidentialInputs.PrivateRequestRow.Parse(row);
        string profile=parsed.ProfilePath,tenant=parsed.TenantArgument,email=parsed.AccountEmail,outcome=parsed.Outcome;
        string? exact=parsed.ExactResultTenant?.ToString("D"),route=parsed.RequiredInteraction;
        bool interactive=parsed.InteractionAllowed,lifetime=parsed.LifetimePipe,
            defaultAccepted=parsed.DefaultAssociationIndependentlyAccepted,persistence=parsed.RequirePersistenceUnconfirmed;
        Need(!parsed.RequireCloseAfterLiveSample); // No real-provider-pending-at-close witness is claimed here.
        int timeout=parsed.TimeoutSeconds;int? close=parsed.CloseAfterMs;
        Need(timeout is >=1 and <=120 && timeout==plan.ProductTimeoutSeconds && Outcomes.Contains(outcome,StringComparer.Ordinal));
        Need(plan.ExpectedExit==(outcome=="success"?0:1) && (outcome!="success" || persistence));
        Need(route is null or "silent" or "interactive");
        Need(route!="interactive" || interactive);
        Need(PrivateExpectation.DirectToken(profile) && profile.Length is >=3 and <=32767 &&
            Regex.IsMatch(profile,"\\A[A-Za-z]:\\\\"));
        Need(PrivateExpectation.DirectToken(email) && email.Length is >=3 and <=320 && Regex.IsMatch(email,"\\A[^@]+@[^@]+\\z"));
        Need(exact is null || GuidText(exact));
        Need(tenant=="common" || GuidText(tenant) && exact is not null && string.Equals(tenant,exact,StringComparison.OrdinalIgnoreCase));
        Need(close is null || lifetime && close>=0 && close<timeout*1000);
        Need((slot==Slot.R9)==close.HasValue);
        string[] scopes=parsed.Scopes;
        string? resource=null;
        foreach(string scope in scopes)
        {
            Need(PrivateExpectation.DirectToken(scope) && scope.Length is >=1 and <=2048);
            int slash=scope.LastIndexOf('/');
            Need(slash==36 && slash<scope.Length-1 && GuidText(scope[..slash]) && !scope[(slash+1)..].Contains('/'));
            resource ??= scope[..slash];Need(resource==scope[..slash]);
        }
        Need(scopes.Distinct(StringComparer.Ordinal).Count()==scopes.Length);
        Need(!scopes.Any(s=>s.EndsWith("/.default",StringComparison.Ordinal)) || scopes.Length==1 && defaultAccepted);
        var args=new List<string> { "authenticate","--protocol","1","--profile",profile,"--account-email",email,
            "--interaction",interactive?"interactive-if-needed":"non-interactive-only","--tenant",tenant,
            "--timeout-seconds",timeout.ToString(CultureInfo.InvariantCulture),"--telemetry","off" };
        foreach(string scope in scopes){args.Add("--scope");args.Add(scope);}
        if(lifetime)args.Add("--cancel-on-stdin-close");
        var result=new PrivateExpectation { Arguments=args.ToArray(),SoleLaunchIdentityPremiseAccepted=soleLaunchAccepted,
            TargetedStopPremiseAccepted=targetedStopAccepted };
        _=result.Command(plan);return result;
    }
}
