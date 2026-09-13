namespace Authentication.Core;

// This value describes a prepared result, not a successful write or process exit.
public sealed record SerializedResult(byte[] Utf8Json, int ExitCode)
{
    public override string ToString() => nameof(SerializedResult);
}

public static class ResultProjection
{
    // The host supplies only the authoritative committed outcome. This red seam
    // deliberately lacks success/failure projection; it never performs transport I/O.
    public static SerializedResult Serialize(AuthenticationOutcome outcome) =>
        new("{\"protocol\":1,\"outcome\":\"internal_failure\",\"reason\":\"internal_failure\"}\n"u8.ToArray(), 1);
}
