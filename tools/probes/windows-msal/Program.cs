using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensibility;

// Research only. The accepted protocol, not this executable, authorizes each attempt.
internal static class Program
{
    internal const string ClientId = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1";
    internal const string Scope = "499b84ac-1321-427f-aa17-267ca6975798/.default";
    private static readonly byte[] GitPrefix = Encoding.ASCII.GetBytes("001e# service=git-upload-pack\n0000");
    private static string output = "";
    private static int completed;
    private static Observation observation = new();
    private static readonly CancellationTokenSource cancellation = new();
    private static System.Threading.Timer? watchdog;

    [STAThread]
    private static void Main(string[] args)
    {
        // Neither inputs nor exception messages are written to output.
        if (args.Length != 2 || args[0] is not ("self-check" or "inspect" or "silent" or "interactive"))
            Environment.Exit(2);
        output = Path.GetFullPath(args[1]);
        observation.Mode = args[0];
        AppDomain.CurrentDomain.UnhandledException += (_, _) => Finish("unexpected-failure", 2);
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, _) => Finish("unexpected-failure", 2);
        if (args[0] == "self-check")
        {
            SelfCheck();
            return;
        }
        watchdog = new System.Threading.Timer(_ => Cancel("process-timeout"), null,
            TimeSpan.FromSeconds(args[0] == "interactive" ? 360 : 120), Timeout.InfiniteTimeSpan);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        using var form = new Form { Text = "AzureAuth research: " + args[0], Width = 660, Height = 320 };
        var text = new Label
        {
            Left = 20, Top = 15, Width = 605, Height = 70,
            Text = "Enter the exact email of your authorized personal Microsoft account.\n" +
                "Choose only that account if Windows prompts you. Close this window to cancel.\n" +
                "The result file contains outcome flags, never your email or token."
        };
        var email = new TextBox { Name = "RequestedEmail", AccessibleName = "RequestedEmail",
            Left = 20, Top = 95, Width = 605, MaxLength = 320 };
        var resourceLabel = new Label { Left = 20, Top = 130, Width = 605,
            Text = "Designated Azure DevOps Git remote (HTTPS)" };
        var resource = new TextBox { Name = "DesignatedRemote", AccessibleName = "DesignatedRemote",
            Left = 20, Top = 155, Width = 605, MaxLength = 2048 };
        var start = new Button { Name = "StartProbe", AccessibleName = "StartProbe",
            Left = 20, Top = 200, Width = 190, Text = "Start " + args[0] };
        var status = new Label { Left = 225, Top = 207, Width = 395, Text = "Waiting for operator" };
        form.Controls.AddRange(new Control[] { text, email, resourceLabel, resource, start, status });
        form.FormClosing += (_, e) => { e.Cancel = true; Cancel("operator-cancelled"); };
        start.Click += async (_, _) =>
        {
            string requestedEmail = email.Text.Trim();
            Uri? discovery = DiscoveryUri(resource.Text.Trim());
            if (requestedEmail.Length == 0 || !requestedEmail.Contains('@') || discovery is null) return;
            start.Enabled = false;
            email.Enabled = false;
            resource.Enabled = false;
            status.Text = "Running; you can close this window to cancel";
            await Run(args[0], requestedEmail, discovery, form.Handle);
        };
        Application.Run(form);
    }

    private static async Task Run(string mode, string email, Uri discovery, IntPtr window)
    {
        try
        {
            var app = PublicClientApplicationBuilder.Create(ClientId)
                .WithAuthority("https://login.microsoftonline.com/common")
                .WithRedirectUri("http://localhost")
                .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
                {
                    Title = "AzureAuth research",
                    ListOperatingSystemAccounts = true
                })
                .WithParentActivityOrWindow(() => window)
                .WithLogging((_, _, _) => { }, LogLevel.Error, false, false)
                .Build();
            if (!((PublicClientApplication)app).IsBrokerAvailable())
            {
                Finish("broker-unavailable", 2);
                return;
            }
            observation.BrokerAvailable = true;
            var accounts = (await app.GetAccountsAsync().WaitAsync(cancellation.Token)).ToList();
            var matching = accounts.Where(a => ExactMatch(a.Username, email)).ToList();
            observation.VisibleAccounts = Bucket(accounts.Count);
            observation.ExactMatches = Bucket(matching.Count);
            observation.VisibleAccountMissingEmail = accounts.Any(a => string.IsNullOrEmpty(a.Username));
            if (mode == "inspect")
            {
                await Discover(discovery, null);
                Finish("inspected", 0);
                return;
            }
            if (matching.Count > 1) { Finish("account-ambiguous", 2); return; }
            if (mode == "silent" && matching.Count == 0) { Finish("account-not-visible", 2); return; }

            AuthenticationResult result;
            observation.AcquisitionStarted = true;
            if (mode == "silent")
                result = await app.AcquireTokenSilent(new[] { Scope }, matching[0])
                    .ExecuteAsync(cancellation.Token);
            else
            {
                var request = app.AcquireTokenInteractive(new[] { Scope })
                    .WithCustomWebUi(new RejectBrowser());
                request = matching.Count == 1 ? request.WithAccount(matching[0]) : request.WithLoginHint(email);
                result = await request.ExecuteAsync(cancellation.Token);
            }
            observation.ProviderReturnedResult = true;
            observation.TokenPresent = !string.IsNullOrEmpty(result.AccessToken);
            observation.EmailPresent = !string.IsNullOrEmpty(result.Account?.Username);
            observation.ExactReturnedEmail = ExactMatch(result.Account?.Username, email);
            observation.TenantPresent = !string.IsNullOrEmpty(result.TenantId);
            observation.MsaTenant = result.TenantId == "9188040d-6c67-4c5b-b112-36a304b66dad";
            observation.ScopeMetadataPresent = result.Scopes?.Any() == true;
            observation.RequestedDefaultScopeReported = result.Scopes?.Contains(Scope, StringComparer.OrdinalIgnoreCase) == true;
            observation.Unexpired = result.ExpiresOn > DateTimeOffset.UtcNow;
            if (observation.ExactReturnedEmail && observation.TokenPresent && observation.Unexpired)
                await Discover(discovery, result.AccessToken);
            Finish(observation.ExactReturnedEmail ? "result-email-matched" : "result-email-unverifiable", 0);
        }
        catch (OperationCanceledException) { Finish("cancelled", 2); }
        catch (MsalUiRequiredException) { Finish("interaction-required", 2); }
        catch (MsalServiceException) { Finish("provider-rejected", 2); }
        catch (MsalClientException) { Finish("client-or-broker-failure", 2); }
        catch (BrowserBlockedException) { Finish("browser-fallback-blocked", 2); }
        catch { Finish("unexpected-failure", 2); }
    }

    private static bool ExactMatch(string? observed, string requested) =>
        !string.IsNullOrEmpty(observed) && string.Equals(observed, requested, StringComparison.OrdinalIgnoreCase);
    private static string Bucket(int count) => count == 0 ? "zero" : count == 1 ? "one" : "multiple";

    private static Uri? DiscoveryUri(string remote)
    {
        if (!Uri.TryCreate(remote, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            uri.Host != "dev.azure.com")
            return null;
        var segments = uri.AbsolutePath.TrimEnd('/').Split('/');
        if (segments.Length < 4 || segments[^2] != "_git" || segments[^1].Length == 0) return null;
        return new Uri(uri.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/info/refs?service=git-upload-pack");
    }

    private static async Task Discover(Uri uri, string? token)
    {
        observation.ResourceAttempted = true;
        observation.ResourceAuthenticated = token is not null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            using var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false, UseCookies = false, Credentials = null,
                DefaultProxyCredentials = null, MaxResponseHeadersLength = 16, MaxResponseDrainSize = 0
            };
            using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            observation.ResourceStatusCode = (int)response.StatusCode;
            observation.ResourceChallengePresent = response.Headers.WwwAuthenticate.Any();
            observation.ResourceContentTypeMatched = string.Equals(response.Content.Headers.ContentType?.MediaType,
                "application/x-git-upload-pack-advertisement", StringComparison.OrdinalIgnoreCase);
            if (observation.ResourceStatusCode == 200 && observation.ResourceContentTypeMatched)
            {
                using var body = await response.Content.ReadAsStreamAsync(deadline.Token);
                var prefix = new byte[GitPrefix.Length];
                int count = await body.ReadAtLeastAsync(prefix, prefix.Length, false, deadline.Token);
                observation.ResourcePrefixMatched = count == prefix.Length && prefix.AsSpan().SequenceEqual(GitPrefix);
            }
            observation.ResourceOutcome = observation.ResourcePrefixMatched ? "git-discovery-recognized" : "not-recognized";
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        { observation.ResourceOutcome = "request-timeout"; }
        catch (HttpRequestException) { observation.ResourceOutcome = "request-failed"; }
        catch (IOException) { observation.ResourceOutcome = "response-failed"; }
    }

    private static void Cancel(string status)
    {
        // The process limit remains effective even if a native call ignores cancellation.
        new Thread(() => { Thread.Sleep(3000); Environment.Exit(4); }) { IsBackground = true }.Start();
        try { cancellation.Cancel(); }
        finally { Finish(status, 2); }
    }

    private static void Finish(string status, int exitCode)
    {
        if (Interlocked.Exchange(ref completed, 1) != 0) return;
        try
        {
            observation.Status = status;
            using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            JsonSerializer.Serialize(file, observation, new JsonSerializerOptions { WriteIndented = true });
            file.Flush(true);
        }
        catch { exitCode = 3; }
        Environment.Exit(exitCode);
    }

    private static void SelfCheck()
    {
        // Synthetic account values exercise the selector and the evidence privacy boundary.
        bool passed = ExactMatch("PERSON@example.invalid", "person@example.invalid") &&
            !ExactMatch(null, "person@example.invalid") &&
            !ExactMatch("alias@example.invalid", "person@example.invalid") &&
            Bucket(0) == "zero" && Bucket(1) == "one" && Bucket(2) == "multiple";
        passed &= DiscoveryUri("https://dev.azure.com/example/project/_git/repo/")?.AbsolutePath ==
                "/example/project/_git/repo/info/refs" &&
            DiscoveryUri("https://person@dev.azure.com/example/project/_git/repo") is null &&
            DiscoveryUri("https://example.invalid/example/project/_git/repo") is null && GitPrefix.Length == 34;
        string json = JsonSerializer.Serialize(observation);
        passed &= !json.Contains("@") && !json.Contains("AccessToken") && !json.Contains("Username");
        Finish(passed ? "self-check-passed" : "self-check-failed", passed ? 0 : 2);
    }

    private sealed class RejectBrowser : ICustomWebUi
    {
        public Task<Uri> AcquireAuthorizationCodeAsync(Uri authorizationUri, Uri redirectUri,
            CancellationToken cancellationToken) => throw new BrowserBlockedException();
    }
    private sealed class BrowserBlockedException : Exception { }

    private sealed class Observation
    {
        public string Mode { get; set; } = "";
        public string Status { get; set; } = "";
        public bool BrokerAvailable { get; set; }
        public string VisibleAccounts { get; set; } = "not-observed";
        public string ExactMatches { get; set; } = "not-observed";
        public bool VisibleAccountMissingEmail { get; set; }
        public bool AcquisitionStarted { get; set; }
        public bool ProviderReturnedResult { get; set; }
        public bool TokenPresent { get; set; }
        public bool EmailPresent { get; set; }
        public bool ExactReturnedEmail { get; set; }
        public bool TenantPresent { get; set; }
        public bool MsaTenant { get; set; }
        public bool ScopeMetadataPresent { get; set; }
        public bool RequestedDefaultScopeReported { get; set; }
        public bool Unexpired { get; set; }
        public bool ResourceAttempted { get; set; }
        public bool ResourceAuthenticated { get; set; }
        public int ResourceStatusCode { get; set; }
        public bool ResourceChallengePresent { get; set; }
        public bool ResourceContentTypeMatched { get; set; }
        public bool ResourcePrefixMatched { get; set; }
        public string ResourceOutcome { get; set; } = "not-observed";
    }
}
