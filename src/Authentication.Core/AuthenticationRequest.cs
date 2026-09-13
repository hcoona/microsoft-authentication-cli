namespace Authentication.Core;

// This is the application boundary after CLI/Profile admission. It is not a second
// public wire protocol, and it does not select or provision a Client Profile.
public sealed record AuthenticationRequest(
    string AccountEmail,
    IReadOnlyList<string> Scopes,
    bool InteractionAllowed,
    Guid? ExactTenant)
{
    public override string ToString() => nameof(AuthenticationRequest);
}

public enum AuthenticationFailure
{
    InternalFailure,
    InteractionRequired,
    AccountAmbiguous,
    IdentityValidationFailed,
}

public sealed record AuthenticationOutcome(
    TokenCandidate? Success,
    AuthenticationFailure? Failure,
    bool PersistenceUnconfirmed = false)
{
    public override string ToString() => Failure?.ToString() ?? "Success";
}

public sealed record ProviderAccount(string? Email, object Handle)
{
    public override string ToString() => nameof(ProviderAccount);
}

public sealed record TokenCandidate(
    string AccessToken,
    string? Email,
    Guid? Tenant,
    IReadOnlyList<string> Scopes,
    string TokenType,
    DateTimeOffset ExpiresOn,
    Guid OperationId)
{
    public override string ToString() => nameof(TokenCandidate);
}

public interface IAuthenticationProvider
{
    Task<IReadOnlyList<ProviderAccount>> GetAccountsAsync(CancellationToken cancellationToken);

    Task<TokenCandidate> AcquireSilentAsync(
        AuthenticationRequest request,
        ProviderAccount account,
        Guid operationId,
        CancellationToken cancellationToken);
}

public interface IRequestHost
{
    TimeProvider Clock { get; }
}
