namespace Authentication.Core;

// Projection of the protocol 1 argument vector, never a JSON input protocol.
public sealed record ParsedRequest(
    string ProfilePath,
    string AccountEmail,
    IReadOnlyList<string> Scopes,
    bool InteractionAllowed,
    string? Tenant,
    int TimeoutSeconds,
    bool CancelOnStdinClose,
    bool TelemetryStderr)
{
    public override string ToString() => nameof(ParsedRequest);
}

public static class RequestSyntax
{
    public static ParsedRequest? Parse(IReadOnlyList<string> arguments)
    {
        // Initial red candidate: all argument vectors are rejected.
        return null;
    }
}
