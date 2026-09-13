using System.Text;
using Authentication.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Authentication.Scenarios;

[TestClass]
public sealed class ProfileSyntaxTests
{
    private const string ClientId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string Tenant = "11111111-2222-3333-4444-555555555555";
    private const string ProfileJson = """
        {
          "schemaVersion": 1,
          "name": "synthetic-selected-profile",
          "clientId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
          "cloud": "public",
          "tenantPolicy": { "kind": "multitenant" },
          "integration": "windows-wam",
          "registration": {
            "owner": "Synthetic external owner",
            "externalDependency": true,
            "supportNotice": "Synthetic public configuration; no support commitment."
          }
        }
        """;

    [TestMethod]
    public void ExplicitOrdinaryProfilePreservesPublicClientAndOwnershipMetadata()
    {
        var profile = Parse(ProfileJson);

        Assert.IsNotNull(profile);
        Assert.AreEqual("synthetic-selected-profile", profile.Name);
        Assert.AreEqual(new Guid(ClientId), profile.ClientId);
        Assert.IsNull(profile.FixedTenant);
        Assert.AreEqual("windows-wam", profile.Integration);
        Assert.AreEqual("Synthetic external owner", profile.RegistrationOwner);
        Assert.AreEqual("Synthetic public configuration; no support commitment.", profile.SupportNotice);
    }

    [TestMethod]
    public void LegacyCandidateRetainsItsExactExternalRegistration()
    {
        var profile = Parse(LegacyProfileJson());

        Assert.IsNotNull(profile);
        Assert.AreEqual(new Guid("872cd9fa-d31f-45e0-9eab-6e460a02d1f1"), profile.ClientId);
        Assert.AreEqual("Microsoft", profile.RegistrationOwner);
        Assert.AreEqual("visual-studio-legacy-wam", profile.Integration);
        Assert.IsNull(profile.FixedTenant);
    }

    [TestMethod]
    public void SingleTenantDocumentPreservesItsFixedTenant()
    {
        var profile = Parse(WithSingleTenant(ProfileJson));

        Assert.IsNotNull(profile);
        Assert.AreEqual(new Guid(Tenant), profile.FixedTenant);
        Assert.AreEqual("windows-wam", profile.Integration);
    }

    [TestMethod]
    public void ProfileAtTheByteLimitIsAccepted()
    {
        var document = Encoding.UTF8.GetBytes(ProfileJson);
        var payload = new byte[64 * 1024];
        payload.AsSpan().Fill((byte)' ');
        document.CopyTo(payload, 0);

        Assert.IsNotNull(ProfileSyntax.Parse(payload));
    }

    [TestMethod]
    [DataRow("unsupported-version")]
    [DataRow("unknown-root-field")]
    [DataRow("duplicate-root-field")]
    [DataRow("unknown-tenant-field")]
    [DataRow("duplicate-tenant-field")]
    [DataRow("unknown-registration-field")]
    [DataRow("duplicate-registration-field")]
    [DataRow("unsupported-cloud")]
    [DataRow("unsupported-integration")]
    [DataRow("invalid-client")]
    [DataRow("unacknowledged-external-owner")]
    [DataRow("missing-owner")]
    [DataRow("missing-single-tenant")]
    [DataRow("legacy-wrong-client")]
    [DataRow("legacy-wrong-owner")]
    [DataRow("legacy-fixed-tenant")]
    public void InvalidProfileCannotConfigureAuthentication(string defect)
    {
        var document = defect switch
        {
            "unsupported-version" => ProfileJson.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 2"),
            "unknown-root-field" => ProfileJson.Replace("\"schemaVersion\":", "\"unknown\": true, \"schemaVersion\":"),
            "duplicate-root-field" => ProfileJson.Replace("\"schemaVersion\":", "\"schemaVersion\": 1, \"schemaVersion\":"),
            "unknown-tenant-field" => ProfileJson.Replace("\"kind\":", "\"unknown\": true, \"kind\":"),
            "duplicate-tenant-field" => ProfileJson.Replace("\"kind\":", "\"kind\": \"multitenant\", \"kind\":"),
            "unknown-registration-field" => ProfileJson.Replace("\"owner\":", "\"unknown\": true, \"owner\":"),
            "duplicate-registration-field" => ProfileJson.Replace("\"owner\":", "\"owner\": \"First owner\", \"owner\":"),
            "unsupported-cloud" => ProfileJson.Replace("\"public\"", "\"arbitrary-cloud\""),
            "unsupported-integration" => ProfileJson.Replace("\"windows-wam\"", "\"browser\""),
            "invalid-client" => ProfileJson.Replace(ClientId, "not-a-guid"),
            "unacknowledged-external-owner" => ProfileJson.Replace("\"externalDependency\": true", "\"externalDependency\": false"),
            "missing-owner" => ProfileJson.Replace("\"owner\": \"Synthetic external owner\",", ""),
            "missing-single-tenant" => ProfileJson.Replace("\"multitenant\"", "\"single-tenant\""),
            "legacy-wrong-client" => LegacyProfileJson().Replace("872cd9fa-d31f-45e0-9eab-6e460a02d1f1", ClientId),
            "legacy-wrong-owner" => LegacyProfileJson().Replace("\"Microsoft\"", "\"Synthetic external owner\""),
            "legacy-fixed-tenant" => WithSingleTenant(LegacyProfileJson()),
            _ => throw new InvalidOperationException("Unknown synthetic defect."),
        };

        Assert.IsNull(Parse(document));
    }

    [TestMethod]
    public void OversizedOtherwiseValidProfileIsRejected()
    {
        Assert.IsNull(Parse(ProfileJson + new string(' ', 64 * 1024)));
    }

    [TestMethod]
    public void MalformedUtf8CannotBeSilentlyReplaced()
    {
        var document = Encoding.UTF8.GetBytes(ProfileJson);
        document[Array.IndexOf(document, (byte)'S')] = 0xff;

        Assert.IsNull(ProfileSyntax.Parse(document));
    }

    [TestMethod]
    [DataRow(null, null)]
    [DataRow("common", null)]
    [DataRow(Tenant, Tenant)]
    public void MultitenantProfilePreservesAnExplicitTenantOtherwiseUsesCommon(string? selector, string? expected)
    {
        var profile = SyntheticProfile(null);

        var valid = ProfileSyntax.TryResolveTenant(profile, selector, out var exactTenant);
        Guid? expectedTenant = expected is null ? null : new Guid(expected);

        Assert.IsTrue(valid);
        Assert.AreEqual(expectedTenant, exactTenant);
    }

    [TestMethod]
    [DataRow((object?)null)]
    [DataRow(Tenant)]
    public void SingleTenantProfileKeepsItsFixedTenant(string? selector)
    {
        var profile = SyntheticProfile(new Guid(Tenant));

        var valid = ProfileSyntax.TryResolveTenant(profile, selector, out var exactTenant);

        Assert.IsTrue(valid);
        Assert.AreEqual(new Guid(Tenant), exactTenant);
    }

    [TestMethod]
    [DataRow("common")]
    [DataRow("99999999-8888-7777-6666-555555555555")]
    public void ConflictingTenantCannotOverrideAFixedProfile(string selector)
    {
        Assert.IsFalse(ProfileSyntax.TryResolveTenant(SyntheticProfile(new Guid(Tenant)), selector, out _));
    }

    private static ClientProfile? Parse(string document) => ProfileSyntax.Parse(Encoding.UTF8.GetBytes(document));

    private static ClientProfile SyntheticProfile(Guid? tenant) =>
        new("synthetic-selected-profile", new Guid(ClientId), tenant, "windows-wam",
            "Synthetic external owner", "Synthetic public configuration; no support commitment.");

    private static string LegacyProfileJson() => ProfileJson
        .Replace(ClientId, "872cd9fa-d31f-45e0-9eab-6e460a02d1f1")
        .Replace("\"windows-wam\"", "\"visual-studio-legacy-wam\"")
        .Replace("\"Synthetic external owner\"", "\"Microsoft\"");

    private static string WithSingleTenant(string document) =>
        document.Replace("\"kind\": \"multitenant\"", "\"kind\": \"single-tenant\", \"tenantId\": \"" + Tenant + "\"");
}
