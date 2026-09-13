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
    InvalidRequest,
    Cancelled,
    Denied,
    MechanismUnavailable,
    TemporarilyUnavailable,
    Timeout,
}

public sealed record AuthenticationOutcome(
    TokenCandidate? Success,
    AuthenticationFailure? Failure,
    bool PersistenceUnconfirmed = false,
    bool Interactive = false)
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

    Task<TokenCandidate> AcquireInteractiveAsync(
        AuthenticationRequest request,
        ProviderAccount? account,
        string? claims,
        nint parentWindow,
        Guid operationId,
        CancellationToken cancellationToken) =>
        Task.FromException<TokenCandidate>(new ProviderFailureException(AuthenticationFailure.MechanismUnavailable));
}

public interface IRequestHost
{
    TimeProvider Clock { get; }

    Task<nint> OpenInteractionAsync(CancellationToken cancellationToken) => Task.FromResult<nint>(0);

    Task CloseInteractionAsync() => Task.CompletedTask;
}

// The adapter supplies structured categories, never provider message text. Claims are
// request-local opaque input for the one permitted continuation and are not output.
public sealed class ProviderFailureException(AuthenticationFailure failure, string? claims = null)
    : Exception("Authentication provider failed.")
{
    public AuthenticationFailure Failure { get; } = failure;

    public string? Claims { get; } = claims;
}
