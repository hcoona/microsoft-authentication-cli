using System.Text.Json;
using Authentication.Core;
using Microsoft.Identity.Client;

namespace Authentication.Windows;

// Interpret public provider observations without exporting provider diagnostics.
public static class MsalBoundary
{
    public static ProviderFailureException MapFailure(Exception exception, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var code = (exception as MsalException)?.ErrorCode;

        if (code == "authentication_canceled")
            return new(AuthenticationFailure.Cancelled);

        if (code == "access_denied"
            || exception is MsalServiceException service && HasStructuredDenial(service.ResponseBody))
            return new(AuthenticationFailure.Denied);

        if (code == "user_mismatch")
            return new(AuthenticationFailure.IdentityValidationFailed);

        if (exception is MsalUiRequiredException challenge)
            return new(AuthenticationFailure.InteractionRequired, challenge.Claims,
                challenge.Classification == UiRequiredExceptionClassification.ConsentRequired
                    ? AuthenticationReason.ConsentRequired : AuthenticationReason.None);

        if (code is "platform_not_supported" or "wam_runtime_init_failed"
            || exception is ProviderFailureException { Failure: AuthenticationFailure.MechanismUnavailable })
            return new(AuthenticationFailure.MechanismUnavailable);

        if (exception is MsalException { IsRetryable: true })
            return new(AuthenticationFailure.TemporarilyUnavailable, reason: AuthenticationReason.ProviderTransient);

        if (code is "service_not_available" or "temporarily_unavailable")
            return new(AuthenticationFailure.TemporarilyUnavailable, reason: AuthenticationReason.ServiceTransient);

        if (code == "network_not_available"
            || exception is HttpRequestException
                { HttpRequestError: HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError }
            || exception is OperationCanceledException { InnerException: TimeoutException })
            return new(AuthenticationFailure.TemporarilyUnavailable, reason: AuthenticationReason.NetworkTransient);

        return new(AuthenticationFailure.InternalFailure);
    }

    public static TokenCandidate Project(AuthenticationResult result, Guid operationId) =>
        new(result.AccessToken, result.Account?.Username,
            Guid.TryParse(result.TenantId, out var tenant) ? tenant : null,
            // Missing scopes must reach the coordinator's metadata rejection. An empty
            // observed list has distinct /.default semantics and cannot replace null.
            result.Scopes?.ToArray()!, result.TokenType, result.ExpiresOn, operationId, result.CorrelationId);

    private static bool HasStructuredDenial(string? body)
    {
        if (body is null || body.Length > 8192)
            return false;

        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions
            {
                MaxDepth = 8,
                AllowDuplicateProperties = false,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("error_codes", out var codes)
                || codes.ValueKind != JsonValueKind.Array || codes.GetArrayLength() > 16)
                return false;

            var denied = false;
            foreach (var code in codes.EnumerateArray())
            {
                if (code.ValueKind != JsonValueKind.Number || !code.TryGetInt32(out var value))
                    return false;
                denied |= value == 65004;
            }

            // Recognition follows validation of the complete document and array.
            return denied;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
