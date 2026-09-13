namespace Authentication.Core;

public sealed record ClientProfile(
    string Name,
    Guid ClientId,
    Guid? FixedTenant,
    string Integration,
    string RegistrationOwner,
    string SupportNotice)
{
    public override string ToString() => nameof(ClientProfile);
}

public static class ProfileSyntax
{
    public static ClientProfile? Parse(ReadOnlyMemory<byte> utf8)
    {
        // Initial red candidate: no Profile document is admitted yet.
        return null;
    }

    public static bool TryResolveTenant(ClientProfile profile, string? selector, out Guid? exactTenant)
    {
        exactTenant = null;
        return false;
    }
}
