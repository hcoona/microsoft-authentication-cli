// INERT PROPOSAL. No compilation, import, or execution is authorized by this file.
// C# 5, x64 .NET Framework; mscorlib.dll, System.dll, System.Core.dll only.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal static class WindowsWslObserver
{
    private const bool Admitted = false;
    private const string RootPattern = @"\AC:\\Temp\\azureauth-windows-slice-108\\named-fixtures-[0-9]{4}\z";
    private const string ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private const string ProductHash = "02993d94c5145f32274a8763f27d632e2dcc8e6a06d257551b1501eed9689cc7";
    private const string MsalHash = "9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79";
    private const string GatedLine = "{\"protocol\":1,\"control\":\"gated\",\"outcome\":\"cancelled\"}\n";
    private const string FastLine = "{\"protocol\":1,\"control\":\"fast\",\"outcome\":\"completed\"}\n";
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly UnicodeEncoding Utf16 = new UnicodeEncoding(false, false, true);
    private static readonly Stopwatch Clock = Stopwatch.StartNew();
    private static string Failure;
    private static string Root;
    private static string Mode;
    private static string Nonce;
    private static string AuthorityHash;
    private static string ReadyHash;
    private static string DevicePrefix;
    private static IntPtr Job;
    private static Gate CurrentGate;
    private static Trace CurrentTrace;
    private static readonly List<Child> Children = new List<Child>();
    private static readonly List<Target> Targets = new List<Target>();
    private static readonly object TargetLock = new object();
    private static bool IntentAccepted;
    private static bool ReadinessPublished;
    private static bool ReleaseSeen;
    private static bool ResourceUncertain;
    private static int Polls;

    private static int Main(string[] args)
    {
        if (!Admitted) { Console.Error.WriteLine("INERT: accepted source/protocol/call admission required"); return 2; }
        try
        {
            if (IntPtr.Size != 8) throw new FailureException("observer-bitness");
            if (args.Length == 4 && args[0] == "--control-gated") return ControlGated(args);
            if (args.Length == 3 && args[0] == "--control-fast") return ControlFast(args);
            Run(args);
        }
        catch (FailureException ex) { Fail(ex.Code); }
        catch { Fail("observer-error"); }
        finally
        {
            // This process cannot claim to clean a trace after its own forced death.
            Cleanup();
            Native.Close(ref Job);
            try { WriteFinal(); } catch { Fail("final-receipt"); }
        }
        if (Failure != null) { Console.Error.WriteLine("wsl-observer-failed; preserve evidence; no retry"); return 1; }
        return 0;
    }

    private static void Fail(string code) { Interlocked.CompareExchange(ref Failure, code, null); }
    private static void Require(bool value, string code) { if (!value) throw new FailureException(code); }
    private static void Check(long deadline)
    {
        Require(Clock.ElapsedMilliseconds < Math.Min(deadline, 30000), "deadline");
        if (Failure != null) throw new FailureException(Failure);
    }
    private static void Tick(long deadline)
    {
        Check(deadline);
        Require(++Polls <= 6000, "poll-limit");
        Thread.Sleep(5);
    }
    private sealed class FailureException : Exception
    {
        internal readonly string Code;
        internal FailureException(string code) { Code = code; }
    }

    private static void Run(string[] args)
    {
        Require(args.Length == 6 && args[0] == "--mode" && args[2] == "--root" &&
            args[4] == "--authority-sha256", "arguments");
        Mode = args[1]; Root = args[3]; AuthorityHash = args[5];
        Require(Mode == "calibration" || Mode == "direct-wsl", "mode");
        Require(Regex.IsMatch(Root, RootPattern) && int.Parse(Root.Substring(Root.Length - 4),
            CultureInfo.InvariantCulture) > 110 && IsHash(AuthorityHash), "root-authority");
        AssertDirect(Root);
        byte[] authorityBytes = ReadFixed(Path.Combine(Root, "authority.json"), 16384);
        Require(Hash(authorityBytes) == AuthorityHash, "authority-hash");
        Dictionary<string, string> a = FlatJson.Parse(authorityBytes);
        Keys(a, "schema", "mode", "root", "nonce", "sessionGuid", "observerSha256",
            "productSha256", "msalruntimeSha256", "artifactAcceptanceSha256", "calibrationAcceptanceSha256",
            "inventorySha256", "controllerSha256");
        Require(a["schema"] == "wsl-observer-authority-v1" && a["mode"] == Mode &&
            a["root"] == Root, "authority-shape");
        Nonce = a["nonce"];
        Require(Regex.IsMatch(Nonce, @"\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z"), "nonce");
        Guid sessionGuid;
        Require(Guid.TryParseExact(a["sessionGuid"], "D", out sessionGuid) && sessionGuid != Guid.Empty &&
            sessionGuid != new Guid("9e814aad-3204-11d2-9a82-006008a86939"), "session-guid");
        foreach (string key in new string[] { "observerSha256", "productSha256", "msalruntimeSha256",
            "artifactAcceptanceSha256", "calibrationAcceptanceSha256", "inventorySha256", "controllerSha256" })
            Require(IsHash(a[key]), "authority-pin");
        Require(a["observerSha256"] != ZeroHash && a["inventorySha256"] != ZeroHash &&
            a["controllerSha256"] != ZeroHash, "authority-empty-pin");
        string self = Path.Combine(Root, "observer.exe");
        Require(string.Equals(System.Reflection.Assembly.GetExecutingAssembly().Location, self,
            StringComparison.OrdinalIgnoreCase), "observer-image");
        Require(Hash(ReadFixed(self, 2097152)) == a["observerSha256"], "observer-hash");
        string jobName = @"Local\azureauth-controller-108-" + Root.Substring(Root.Length - 4) + "-" + Nonce;
        Job = Native.OpenJobObject(4, false, jobName);
        bool inJob;
        Require(Job != IntPtr.Zero && Native.IsProcessInJob(Native.GetCurrentProcess(), Job, out inJob) &&
            inJob, "observer-job");
        StringBuilder map = new StringBuilder(32768);
        uint mapCount = Native.QueryDosDevice("C:", map, map.Capacity);
        Require(mapCount > 0 && mapCount < map.Capacity, "drive-mapping");
        DevicePrefix = map.ToString().Split('\0')[0];
        Require(Regex.IsMatch(DevicePrefix, @"\A\\Device\\HarddiskVolume[0-9]+\z"), "drive-mapping-shape");
        foreach (string name in new string[] { "readiness.json", "readiness.json.pending", "final.json",
            "final.json.pending", "release.marker", "product-launch-intent.json" })
            Require(!File.Exists(Path.Combine(Root, name)), "preexisting-control-file");
        if (Mode == "calibration")
        {
            Require(a["productSha256"] == ZeroHash && a["msalruntimeSha256"] == ZeroHash &&
                a["artifactAcceptanceSha256"] == ZeroHash && a["calibrationAcceptanceSha256"] == ZeroHash,
                "calibration-scope");
            foreach (string image in new string[] { "control-gated.exe", "control-fast.exe" })
                Require(Hash(ReadFixed(Path.Combine(Root, image), 2097152)) == a["observerSha256"], "control-hash");
            Targets.Add(new Target("gated", Path.Combine(Root, "control-gated.exe"),
                Quote(Path.Combine(Root, "control-gated.exe")) + " --control-gated " + Quote(Root) +
                " " + Nonce + " gate-calibration.json", 0));
            Targets.Add(new Target("fast", Path.Combine(Root, "control-fast.exe"),
                Quote(Path.Combine(Root, "control-fast.exe")) + " --control-fast " + Quote(Root) + " " + Nonce, 0));
        }
        else
        {
            Require(a["productSha256"] == ProductHash && a["msalruntimeSha256"] == MsalHash &&
                a["artifactAcceptanceSha256"] != ZeroHash && a["calibrationAcceptanceSha256"] != ZeroHash,
                "product-admission");
            Require(Hash(ReadFixed(Path.Combine(Root, @"native\azureauth.exe"), 16777216)) == ProductHash &&
                Hash(ReadFixed(Path.Combine(Root, @"native\msalruntime.dll"), 8388608)) == MsalHash, "product-hash");
            Targets.Add(new Target("product", Path.Combine(Root, @"native\azureauth.exe"), ProductCommand(), 1));
        }
        CurrentGate = new Gate();
        CurrentGate.Initialize(Path.Combine(Root, Mode == "calibration" ? "gate-calibration.json" : "gate-product.json"));
        string sessionName = "AzureAuthSliceWsl-" + Root.Substring(Root.Length - 4) + "-" + Mode + "-" + Nonce;
        CurrentTrace = new Trace(sessionName, sessionGuid);
        CurrentTrace.Start();
        CurrentGate.RequirePending();
        Check(5000);
        Dictionary<string, string> ready = Record("wsl-observer-readiness-v1");
        ready.Add("traceStarted", "true"); ready.Add("consumerThreadStarted", "true");
        ready.Add("gateGranted", "true"); ready.Add("supportedVersions", "3,4");
        ready.Add("deviceMappingSha256", Hash(Utf8.GetBytes(DevicePrefix)));
        ReadyHash = WriteAtomic("readiness.json", ready);
        ReadinessPublished = true;
        if (Mode == "calibration") Calibration(); else Direct();
        Require(CurrentGate.Released && CurrentGate.Completed, "gate-completion");
        CurrentTrace.StopAndDrain(Math.Min(27000, Clock.ElapsedMilliseconds + 9000));
        lock (TargetLock) foreach (Target target in Targets) target.RequireComplete();
        Check(30000);
    }

    private static void Calibration()
    {
        Child gated = Child.Start(Targets[0], "gate-calibration.json");
        long deadline = Math.Min(13000, Clock.ElapsedMilliseconds + 6000);
        bool closedInput = false;
        while (!gated.Signaled || !gated.StreamsEnded)
        {
            CurrentGate.Poll();
            if (CurrentGate.HeldBreak && !closedInput) { gated.CloseInput(); closedInput = true; }
            if (gated.FirstLine) CurrentGate.Release(250);
            Require(!gated.StreamError, "control-stream");
            Tick(deadline);
        }
        Require(closedInput && CurrentGate.HeldBreak && gated.Matches(GatedLine) && gated.ExitCode == 0,
            "gated-control-result");
        Require(CurrentGate.Released && CurrentGate.Completed, "gated-control-drain");
        Child fast = Child.Start(Targets[1], null);
        fast.CloseInput();
        deadline = Math.Min(18000, Clock.ElapsedMilliseconds + 3000);
        while (!fast.Signaled || !fast.StreamsEnded) { Require(!fast.StreamError, "control-stream"); Tick(deadline); }
        Require(fast.Matches(FastLine) && fast.ExitCode == 0, "fast-control-result");
        // Creation handles remain held separately. No OpenProcess is used for the fast role.
    }

    private static void Direct()
    {
        Target product = Targets[0];
        long launchDeadline = Math.Min(10000, Clock.ElapsedMilliseconds + 5000);
        long productDeadline = 0;
        while (true)
        {
            CurrentGate.Poll();
            bool release = File.Exists(Path.Combine(Root, "release.marker"));
            bool started;
            lock (TargetLock) started = product.Starts == 1;
            if ((started || release) && !IntentAccepted) ReadIntent();
            if (release && !ReleaseSeen)
            {
                Require(ReadFixed(Path.Combine(Root, "release.marker"), 0).Length == 0, "release-marker");
                ReleaseSeen = true; CurrentGate.Release(250);
            }
            if (started && productDeadline == 0) productDeadline = Math.Min(16000, Clock.ElapsedMilliseconds + 6000);
            if (IntentAccepted) product.TryOpenOriginal();
            bool ended;
            lock (TargetLock) ended = product.Ends == 1;
            if (ended && ReleaseSeen) break;
            Tick(productDeadline == 0 ? launchDeadline : productDeadline);
        }
        Require(IntentAccepted && ReleaseSeen && CurrentGate.Released && CurrentGate.Completed, "direct-release");
        // Product stdout/stderr, first-LF ordering and proxy completion are independently checked by Linux.
    }

    private static void ReadIntent()
    {
        Dictionary<string, string> i = FlatJson.Parse(ReadFixed(Path.Combine(Root, "product-launch-intent.json"), 8192));
        Keys(i, "schema", "root", "nonce", "authoritySha256", "readinessSha256", "productPath", "productCommandLine", "expectedExit");
        Require(i["schema"] == "wsl-product-launch-intent-v1" && i["root"] == Root && i["nonce"] == Nonce &&
            i["authoritySha256"] == AuthorityHash && i["readinessSha256"] == ReadyHash &&
            i["productPath"] == Targets[0].Image && i["productCommandLine"] == ProductCommand() &&
            i["expectedExit"] == "1", "launch-intent");
        IntentAccepted = true;
    }

    private static string ProductCommand()
    {
        return Path.Combine(Root, @"native\azureauth.exe") + " authenticate --protocol 1 --profile " +
            Path.Combine(Root, "gate-product.json") +
            " --account-email wsl-synthetic@example.invalid --scope https://example.invalid/wsl-cancel" +
            " --interaction non-interactive-only --timeout-seconds 4 --cancel-on-stdin-close --telemetry off";
    }

    private static void Cleanup()
    {
        if (CurrentGate != null)
        {
            try { CurrentGate.Release(250); } catch { ResourceUncertain = true; Fail("gate-cleanup"); }
        }
        foreach (Child child in Children)
        {
            try { child.CloseInput(); child.EnsureStopped(2000); child.Close(); }
            catch { ResourceUncertain = true; Fail("control-cleanup"); }
        }
        foreach (Target target in Targets)
        {
            try { target.EnsureStopped(2000); target.Close(); }
            catch { ResourceUncertain = true; Fail("target-cleanup"); }
        }
        if (CurrentTrace != null)
        {
            try { CurrentTrace.StopAndDrain(Math.Min(29500, Clock.ElapsedMilliseconds + 9000)); }
            catch { ResourceUncertain = true; Fail("trace-cleanup"); }
        }
        if (CurrentGate != null) CurrentGate.FreeIfComplete();
    }

    private static void WriteFinal()
    {
        if (Root == null || Nonce == null) return;
        Dictionary<string, string> record = Record("wsl-observer-final-v1");
        record.Add("passed", Bool(Failure == null)); record.Add("failure", Failure ?? "none");
        record.Add("resourceUncertain", Bool(ResourceUncertain));
        record.Add("intentAccepted", Bool(IntentAccepted)); record.Add("releaseSeen", Bool(ReleaseSeen));
        record.Add("readinessPublished", Bool(ReadinessPublished));
        record.Add("gateGranted", Bool(CurrentGate != null && CurrentGate.Granted));
        record.Add("gateHeldBreak", Bool(CurrentGate != null && CurrentGate.HeldBreak));
        record.Add("gateReleased", Bool(CurrentGate != null && CurrentGate.Released));
        record.Add("gateCompleted", Bool(CurrentGate != null && CurrentGate.Completed));
        record.Add("traceStopped", Bool(CurrentTrace != null && CurrentTrace.Stopped));
        record.Add("consumerCompleted", Bool(CurrentTrace != null && CurrentTrace.Drained));
        record.Add("eventsLost", Num(CurrentTrace == null ? -1 : CurrentTrace.EventsLost));
        record.Add("logBuffersLost", Num(CurrentTrace == null ? -1 : CurrentTrace.LogBuffersLost));
        record.Add("realTimeBuffersLost", Num(CurrentTrace == null ? -1 : CurrentTrace.RealTimeBuffersLost));
        record.Add("callbacks", Num(CurrentTrace == null ? 0 : CurrentTrace.Callbacks));
        lock (TargetLock) foreach (Target t in Targets)
        {
            record.Add(t.Role + "Starts", Num(t.Starts)); record.Add(t.Role + "Ends", Num(t.Ends));
            record.Add(t.Role + "Pid", Num(t.Pid)); record.Add(t.Role + "Exit", Num(t.Exit));
            record.Add(t.Role + "StartQpc", Num(t.StartQpc)); record.Add(t.Role + "EndQpc", Num(t.EndQpc));
            record.Add(t.Role + "PointerBytes", Num(t.PointerBytes)); record.Add(t.Role + "Version", Num(t.Version));
            record.Add(t.Role + "HandleOpened", Bool(t.Handle != IntPtr.Zero || t.HadHandle));
            record.Add(t.Role + "CreationFileTime", Num(t.CreationFileTime));
            record.Add(t.Role + "HandleSignaled", Bool(t.HandleSignaled));
            record.Add(t.Role + "Forced", Bool(t.Forced));
            record.Add(t.Role + "ObjectKeySha256", Hash(BitConverter.GetBytes(t.Key)));
            record.Add(t.Role + "ObjectKeyNonzero", Bool(t.Key != 0));
            record.Add(t.Role + "CreationHandle", Bool(t.CreationHandle));
            record.Add(t.Role + "LateHandleAttempted", Bool(t.OpenAttempted));
            record.Add(t.Role + "CreationPidMatched", Bool(t.CreationHandle && t.Starts == 1 && t.Pid == t.CreatedPid));
            record.Add(t.Role + "ExpectedImageSha256", Hash(Utf8.GetBytes(t.Image)));
            record.Add(t.Role + "ExpectedCommandSha256", Hash(Utf8.GetBytes(t.Command)));
        }
        foreach (Child child in Children) child.AddReceipt(record);
        record.Add("artifactAccepted", "false"); record.Add("continuationAllowed", "false");
        WriteAtomic("final.json", record);
    }

    private static Dictionary<string, string> Record(string schema)
    {
        Dictionary<string, string> r = new Dictionary<string, string>(StringComparer.Ordinal);
        r.Add("schema", schema); r.Add("mode", Mode); r.Add("root", Root); r.Add("nonce", Nonce);
        r.Add("authoritySha256", AuthorityHash); r.Add("elapsedMilliseconds", Num(Clock.ElapsedMilliseconds));
        return r;
    }
    private static string Bool(bool b) { return b ? "true" : "false"; }
    private static string Num(long n) { return n.ToString(CultureInfo.InvariantCulture); }
    private static bool IsHash(string text) { return Regex.IsMatch(text, @"\A[0-9a-f]{64}\z"); }
    private static string Hash(byte[] data)
    {
        using (SHA256 h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
    }
    private static string Quote(string path) { Require(path.IndexOf('"') < 0, "quote"); return "\"" + path + "\""; }
    private static void Keys(Dictionary<string, string> values, params string[] names)
    {
        Require(values.Count == names.Length, "json-keys");
        foreach (string name in names) Require(values.ContainsKey(name), "json-key");
    }
    private static void AssertDirect(string path)
    {
        Require((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "reparse");
    }
    private static byte[] ReadFixed(string path, int cap)
    {
        AssertDirect(path);
        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Require(f.Length >= 0 && f.Length <= cap, "input-size");
            byte[] raw = new byte[(int)f.Length]; int offset = 0;
            while (offset < raw.Length)
            {
                int count = f.Read(raw, offset, raw.Length - offset);
                Require(count > 0, "input-short"); offset += count;
            }
            Require(f.ReadByte() == -1 && f.Length == raw.Length, "input-changed"); return raw;
        }
    }
    private static string WriteAtomic(string name, Dictionary<string, string> record)
    {
        byte[] raw = FlatJson.Encode(record); Require(raw.Length <= 8192, "receipt-limit");
        string pending = Path.Combine(Root, name + ".pending"); string final = Path.Combine(Root, name);
        using (FileStream f = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { f.Write(raw, 0, raw.Length); f.Flush(true); }
        File.Move(pending, final); return Hash(raw);
    }

    private static int ControlFast(string[] args)
    {
        ControlArguments(args[1], args[2]);
        byte[] line = Utf8.GetBytes(FastLine); Stream output = Console.OpenStandardOutput();
        output.Write(line, 0, line.Length); output.Flush(); return 0;
    }
    private static int ControlGated(string[] args)
    {
        ControlArguments(args[1], args[2]); Require(args[3] == "gate-calibration.json", "control-file");
        bool fileOk = false; ManualResetEvent fileDone = new ManualResetEvent(false);
        Thread worker = new Thread(delegate()
        {
            try
            {
                using (FileStream f = new FileStream(Path.Combine(args[1], args[3]), FileMode.Open,
                    FileAccess.Read, FileShare.Read, 1, FileOptions.Asynchronous | FileOptions.SequentialScan))
                    fileOk = f.ReadByte() == 123 && f.ReadByte() == 125 && f.ReadByte() == -1;
            }
            catch { fileOk = false; }
            finally { fileDone.Set(); }
        }); worker.IsBackground = true; worker.Start();
        bool eof = false; ManualResetEvent inputDone = new ManualResetEvent(false);
        Thread input = new Thread(delegate() { try { eof = Console.OpenStandardInput().ReadByte() == -1; }
            catch { eof = false; } finally { inputDone.Set(); } });
        input.IsBackground = true; input.Start();
        if (!inputDone.WaitOne(6000) || !eof) return 2;
        byte[] line = Utf8.GetBytes(GatedLine); Stream output = Console.OpenStandardOutput();
        output.Write(line, 0, line.Length); output.Flush();
        if (!fileDone.WaitOne(1000) || !fileOk) return 2;
        return 0;
    }
    private static void ControlArguments(string root, string nonce)
    {
        Require(Regex.IsMatch(root, RootPattern) && int.Parse(root.Substring(root.Length - 4),
            CultureInfo.InvariantCulture) > 110 && Regex.IsMatch(nonce,
            @"\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z"), "control-arguments");
    }

    private sealed class Gate
    {
        private IntPtr file, signal, overlapped, input, output;
        private bool requested, closeAttempted, releaseWaitUsed;
        internal bool Granted, HeldBreak, Released, Completed;
        internal void Initialize(string path)
        {
            byte[] bytes = ReadFixed(path, 2);
            Require(bytes.Length == 2 && bytes[0] == 123 && bytes[1] == 125, "gate-bytes");
            file = Native.CreateFile(path, 0x80000000, 0, IntPtr.Zero, 3, 0x40200000, IntPtr.Zero);
            if (file == new IntPtr(-1)) { file = IntPtr.Zero; throw new FailureException("gate-open"); }
            Native.FileInformation info;
            Require(Native.GetFileInformationByHandle(file, out info) && (info.Attributes & 0x410) == 0 &&
                info.SizeHigh == 0 && info.SizeLow == 2 && info.Links == 1, "gate-identity");
            signal = Native.CreateEvent(IntPtr.Zero, true, false, null);
            Require(signal != IntPtr.Zero, "gate-event");
            overlapped = Native.Allocate(32); input = Native.Allocate(12); output = Native.Allocate(24);
            Marshal.WriteIntPtr(overlapped, 24, signal);
            Marshal.WriteInt16(input, 0, 1); Marshal.WriteInt16(input, 2, 12);
            Marshal.WriteInt32(input, 4, 3); Marshal.WriteInt32(input, 8, 1);
            bool result = Native.DeviceIoControl(file, 0x00090240, input, 12, output, 24,
                IntPtr.Zero, overlapped);
            int error = Marshal.GetLastWin32Error();
            requested = !result && error == 997;
            Require(!result && error == 997, "gate-grant"); Granted = true;
        }
        internal void RequirePending()
        {
            Require(Granted && !Released && !HeldBreak && Native.WaitForSingleObject(signal, 0) == 258,
                "gate-not-pending");
        }
        internal void Poll()
        {
            if (Released || Completed) return;
            uint state = Native.WaitForSingleObject(signal, 0);
            if (state == 258) return;
            Require(state == 0, "gate-wait");
            uint transferred;
            bool ok = Native.GetOverlappedResultEx(file, overlapped, out transferred, 0, false);
            Completed = unchecked((uint)Marshal.ReadInt64(overlapped)) != 0x103;
            Require(ok && Completed && transferred == 24 && Marshal.ReadInt64(overlapped) == 0,
                "gate-break-status");
            ValidateBreak(); HeldBreak = true;
        }
        private void ValidateBreak()
        {
            int flags = Marshal.ReadInt32(output, 12);
            Require(Marshal.ReadInt16(output, 0) == 1 && Marshal.ReadInt16(output, 2) == 24 &&
                Marshal.ReadInt32(output, 4) == 3 && Marshal.ReadInt32(output, 8) == 1 &&
                (flags & 1) != 0 && (flags & ~3) == 0, "gate-break-shape");
            if ((flags & 2) != 0)
            {
                uint access = unchecked((uint)Marshal.ReadInt32(output, 16));
                Require(Marshal.ReadInt16(output, 20) == 1 && (access & 0x80000001) != 0 &&
                    (access & 0x00010116) == 0, "gate-break-access");
            }
        }
        internal void Release(int milliseconds)
        {
            if (!Released)
            {
                Require(!closeAttempted, "gate-close-unconfirmed"); closeAttempted = true;
                if (file != IntPtr.Zero) Require(Native.CloseHandle(file), "gate-close");
                file = IntPtr.Zero; Released = true;
            }
            if (!requested) Completed = true;
            if (Completed) return;
            uint allowance = releaseWaitUsed ? 0 : Remaining(milliseconds); releaseWaitUsed = true;
            uint wait = Native.WaitForSingleObject(signal, allowance);
            if (wait == 0)
            {
                uint status = unchecked((uint)Marshal.ReadInt64(overlapped));
                Completed = status != 0x103;
                Require(Completed && (status == 0x216 || status == 0 || status == 0xc0000120),
                    "gate-close-status");
            }
            Require(Completed, "gate-close-pending");
        }
        internal void FreeIfComplete()
        {
            if (!Released || !Completed) return; // Deliberately retain storage until process teardown.
            if (signal != IntPtr.Zero) { Native.CloseHandle(signal); signal = IntPtr.Zero; }
            Native.Free(ref input); Native.Free(ref output); Native.Free(ref overlapped);
        }
    }

    private static uint Remaining(int maximum)
    {
        return (uint)Math.Max(0, Math.Min(maximum, 30000 - Clock.ElapsedMilliseconds));
    }

    private sealed class Target
    {
        internal readonly string Role, Image, Command;
        internal readonly int ExpectedExit;
        internal int Starts, Ends, Exit, Version, PointerBytes;
        internal uint Pid;
        internal uint CreatedPid;
        internal ulong Key;
        internal long StartQpc, EndQpc, CreationFileTime;
        internal IntPtr Handle;
        internal bool HadHandle, HandleSignaled, Forced, OpenAttempted, CreationHandle;
        internal Target(string role, string image, string command, int expectedExit)
        { Role = role; Image = image; Command = command; ExpectedExit = expectedExit; }
        internal void RequireComplete()
        {
            Require(Starts == 1 && Ends == 1 && Key != 0 && Pid != 0 && EndQpc >= StartQpc &&
                Exit == ExpectedExit && PointerBytes == 8 && (Version == 3 || Version == 4), "target-etw-incomplete");
            Require(!Forced, "target-forced");
            if (Role != "product") Require(CreationHandle && CreatedPid == Pid, "creation-truth");
            if (Handle != IntPtr.Zero)
            {
                HandleSignaled = Native.WaitForSingleObject(Handle, 0) == 0;
                uint code;
                Require(HandleSignaled && Native.GetExitCodeProcess(Handle, out code) &&
                    code == unchecked((uint)ExpectedExit), "target-handle-exit");
            }
        }
        internal void TryOpenOriginal()
        {
            uint pid;
            lock (TargetLock)
            {
                if (OpenAttempted || Starts != 1 || Ends == 1) return;
                OpenAttempted = true; pid = Pid;
            }
            IntPtr candidate = Native.OpenProcess(0x00101001, false, pid);
            if (candidate == IntPtr.Zero) return; // Complete matching END remains a possible evidence path.
            try
            {
                Require(Native.GetProcessId(candidate) == pid && SameImage(Native.Image(candidate), Image),
                    "late-handle-identity");
                long created = 0, exited, kernel, user;
                Require(Native.GetProcessTimes(candidate, out created, out exited, out kernel, out user),
                    "late-handle-time");
                Handle = candidate; HadHandle = true; CreationFileTime = created; candidate = IntPtr.Zero;
            }
            finally { if (candidate != IntPtr.Zero) Native.CloseHandle(candidate); }
        }
        internal void EnsureStopped(int milliseconds)
        {
            if (Handle == IntPtr.Zero)
            {
                if ((Starts != 0 || (Role == "product" && ReadinessPublished)) && Ends != 1)
                { ResourceUncertain = true; Fail("target-lifetime-unknown"); }
                return;
            }
            if (Native.WaitForSingleObject(Handle, 0) == 0) { HandleSignaled = true; return; }
            Require(!Forced, "target-still-live");
            Forced = true; Fail("target-forced");
            Require(Native.TerminateProcess(Handle, 211), "target-terminate");
            Require(Native.WaitForSingleObject(Handle, Remaining(milliseconds)) == 0, "target-terminate-wait");
            HandleSignaled = true;
        }
        internal void Close()
        {
            if (Handle != IntPtr.Zero && HandleSignaled) Native.Close(ref Handle);
        }
    }

    private sealed class ProcessEvent
    {
        internal uint Pid;
        internal ulong Key;
        internal int Exit, Version, Width;
        internal long Qpc;
        internal string Image, Command;
    }
    private static readonly List<ProcessEvent> EarlyEnds = new List<ProcessEvent>();
    private static void Associate(ProcessEvent e, int opcode)
    {
        lock (TargetLock)
        {
            if (opcode == 1)
            {
                Target target = null;
                foreach (Target t in Targets)
                {
                    if (SameImage(e.Image, t.Image)) { target = t; break; }
                    if (string.Equals(e.Image, Path.GetFileName(t.Image), StringComparison.OrdinalIgnoreCase))
                        throw new FailureException("short-target-image");
                }
                if (target == null) return;
                Require(e.Command == target.Command && target.Starts == 0 && e.Key != 0 &&
                    e.Pid != 0 && e.Width == 8, "target-start-identity");
                if (target.Pid != 0) Require(target.Pid == e.Pid, "creation-event-pid");
                target.Starts = 1; target.Pid = e.Pid; target.Key = e.Key; target.StartQpc = e.Qpc;
                target.Version = e.Version; target.PointerBytes = e.Width;
                for (int i = EarlyEnds.Count - 1; i >= 0; i--)
                    if (EarlyEnds[i].Pid == e.Pid && EarlyEnds[i].Key == e.Key)
                    { ApplyEnd(target, EarlyEnds[i]); EarlyEnds.RemoveAt(i); }
            }
            else
            {
                foreach (Target t in Targets)
                    if (t.Starts == 1 && t.Pid == e.Pid && t.Key == e.Key) { ApplyEnd(t, e); return; }
                Require(EarlyEnds.Count < 256, "early-end-cap");
                // No unrelated image, command, SID or parent data is retained in this bounded join queue.
                e.Image = null; e.Command = null; EarlyEnds.Add(e);
            }
        }
    }
    private static void ApplyEnd(Target target, ProcessEvent e)
    {
        Require(target.Ends == 0 && e.Width == target.PointerBytes && e.Version == target.Version &&
            e.Qpc >= target.StartQpc, "target-end-identity");
        target.Ends = 1; target.EndQpc = e.Qpc; target.Exit = e.Exit;
    }
    private static bool SameImage(string actual, string expected)
    {
        if (actual.StartsWith(DevicePrefix + "\\", StringComparison.OrdinalIgnoreCase))
            actual = "C:" + actual.Substring(DevicePrefix.Length);
        if (actual.StartsWith(@"\\?\C:\", StringComparison.OrdinalIgnoreCase)) actual = actual.Substring(4);
        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }
    private sealed class Trace
    {
        private readonly string name;
        private readonly Guid guid;
        private IntPtr properties, logfile, namePointer;
        private ulong session, consumer = ulong.MaxValue;
        private Thread worker;
        private Native.RecordCallback callback;
        private Native.BufferCallback bufferCallback;
        private bool owned, stopAttempted, consumerCloseAttempted, finalized;
        private uint processResult = uint.MaxValue;
        private long copiedBytes;
        internal bool Stopped, Drained;
        internal int Callbacks, EventsLost = -1, LogBuffersLost = -1, RealTimeBuffersLost = -1;
        internal Trace(string name, Guid guid) { this.name = name; this.guid = guid; }
        internal void Start()
        {
            byte[] nameBytes = Utf16.GetBytes(name + "\0");
            Require(nameBytes.Length <= 1024, "trace-name");
            properties = Native.Allocate(120 + nameBytes.Length);
            Marshal.WriteInt32(properties, 0, 120 + nameBytes.Length);
            Marshal.Copy(guid.ToByteArray(), 0, IntPtr.Add(properties, 24), 16);
            Marshal.WriteInt32(properties, 40, 1); Marshal.WriteInt32(properties, 44, 0x00020000);
            Marshal.WriteInt32(properties, 48, 64); Marshal.WriteInt32(properties, 52, 4);
            Marshal.WriteInt32(properties, 56, 8); Marshal.WriteInt32(properties, 64, 0x12000100);
            Marshal.WriteInt32(properties, 68, 1); Marshal.WriteInt32(properties, 72, 0x10000001);
            Marshal.WriteInt32(properties, 116, 120);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(properties, 120), nameBytes.Length);
            Require(Native.StartTrace(out session, name, properties) == 0, "trace-start"); owned = true;
            Require(Native.ControlTrace(session, name, properties, 0) == 0, "trace-query");
            int minimum = Marshal.ReadInt32(properties, 52), maximum = Marshal.ReadInt32(properties, 56);
            int allocated = Marshal.ReadInt32(properties, 80);
            Require(Marshal.ReadInt32(properties, 48) == 64 && minimum >= 2 && minimum <= 8 &&
                maximum >= minimum && maximum <= 8 && allocated >= 2 && allocated <= 8 &&
                Marshal.ReadInt32(properties, 64) == 0x12000100 && Marshal.ReadInt32(properties, 72) == 0x10000001,
                "trace-buffer-shape");
            logfile = Native.Allocate(448); namePointer = Marshal.StringToHGlobalUni(name);
            Marshal.WriteIntPtr(logfile, 8, namePointer); Marshal.WriteInt32(logfile, 28, 0x10001100);
            callback = OnRecord; bufferCallback = OnBuffer;
            Marshal.WriteIntPtr(logfile, 400, Marshal.GetFunctionPointerForDelegate(bufferCallback));
            Marshal.WriteIntPtr(logfile, 424, Marshal.GetFunctionPointerForDelegate(callback));
            consumer = Native.OpenTrace(logfile);
            Require(consumer != ulong.MaxValue, "trace-open");
            ManualResetEvent entered = new ManualResetEvent(false);
            worker = new Thread(delegate()
            {
                entered.Set(); ulong handle = consumer;
                try { processResult = Native.ProcessTrace(ref handle, 1, IntPtr.Zero, IntPtr.Zero); }
                catch { processResult = uint.MaxValue; Fail("consumer-worker"); }
            }); worker.IsBackground = true; worker.Start();
            Require(entered.WaitOne((int)Remaining(1000)), "consumer-ready");
            entered.Close();
        }
        private uint OnBuffer(IntPtr data)
        {
            try
            {
                if (Marshal.ReadInt32(data, 416) != 0) Fail("consumer-buffer-loss");
                return Failure == null ? 1U : 0U;
            }
            catch { Fail("buffer-callback"); return 0; }
        }
        private void OnRecord(IntPtr record)
        {
            try
            {
                if (Failure != null) return;
                Require(Interlocked.Increment(ref Callbacks) <= 65536, "callback-limit");
                byte[] provider = new byte[16]; Marshal.Copy(IntPtr.Add(record, 24), provider, 0, 16);
                if (new Guid(provider) != new Guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c")) return;
                int opcode = Marshal.ReadByte(record, 45); if (opcode != 1 && opcode != 2) return;
                int version = Marshal.ReadByte(record, 42);
                Require(version == 3 || version == 4, "event-version");
                int flags = (ushort)Marshal.ReadInt16(record, 4);
                Require((flags & 0x60) == 0x20 || (flags & 0x60) == 0x40, "event-width");
                int width = (flags & 0x40) != 0 ? 8 : 4;
                int length = (ushort)Marshal.ReadInt16(record, 86);
                Require(length > 0 && Interlocked.Add(ref copiedBytes, length) <= 16777216, "event-byte-cap");
                byte[] raw = new byte[length]; Marshal.Copy(Marshal.ReadIntPtr(record, 96), raw, 0, length);
                ProcessEvent e = Decode(raw, version, width); e.Qpc = Marshal.ReadInt64(record, 16);
                Associate(e, opcode);
            }
            catch (FailureException ex) { Fail(ex.Code); }
            catch { Fail("event-decode"); }
        }
        internal void StopAndDrain(long deadline)
        {
            if (finalized) return;
            if (!owned) { FreeIfFinished(); return; }
            if (!stopAttempted)
            {
                stopAttempted = true;
                uint result = Native.ControlTrace(session, name, properties, 1);
                if (result == 0)
                {
                    Stopped = true;
                    EventsLost = Marshal.ReadInt32(properties, 88);
                    LogBuffersLost = Marshal.ReadInt32(properties, 96);
                    RealTimeBuffersLost = Marshal.ReadInt32(properties, 100);
                }
                else Fail("trace-stop");
            }
            if (worker != null)
            {
                int remaining = (int)Math.Max(0, Math.Min(deadline, 29500) - Clock.ElapsedMilliseconds);
                if (!worker.Join(remaining))
                {
                    Fail("consumer-drain"); CloseConsumer();
                    Require(worker.Join((int)Remaining(100)), "consumer-live");
                }
                Drained = Stopped && processResult == 0 && !consumerCloseAttempted;
            }
            CloseConsumer();
            FreeIfFinished();
            Require(Stopped && Drained && EventsLost == 0 && LogBuffersLost == 0 && RealTimeBuffersLost == 0,
                "trace-finalization");
            finalized = true;
        }
        private void CloseConsumer()
        {
            if (consumer == ulong.MaxValue || consumerCloseAttempted) return;
            consumerCloseAttempted = true;
            uint result = Native.CloseTrace(consumer);
            Require(result == 0 || result == 7007, "consumer-close");
        }
        private void FreeIfFinished()
        {
            if (worker != null && worker.IsAlive) return; // Retain callbacks/buffers until process teardown.
            Native.Free(ref logfile); Native.Free(ref namePointer);
            if (!owned || Stopped) Native.Free(ref properties);
        }
    }

    private static ProcessEvent Decode(byte[] raw, int version, int width)
    {
        ProcessEvent e = new ProcessEvent(); e.Version = version; e.Width = width;
        e.Key = ReadUnsigned(raw, 0, width); e.Pid = (uint)ReadUnsigned(raw, width, 4);
        e.Exit = unchecked((int)ReadUnsigned(raw, 16 + width - 4, 4));
        int sid = (version == 4 ? 28 : 24) + 2 * (width - 4);
        int image;
        if (ReadUnsigned(raw, sid, 4) == 0) image = sid + 4;
        else
        {
            int token = 2 * width;
            Require(ReadUnsigned(raw, sid + token, 1) == 1, "sid-revision");
            int authorities = (int)ReadUnsigned(raw, sid + token + 1, 1);
            Require(authorities <= 15, "sid-count"); image = sid + token + 8 + 4 * authorities;
        }
        int next = image; e.Image = ReadString(raw, ref next, false);
        e.Command = ReadString(raw, ref next, true);
        if (version == 4) { ReadString(raw, ref next, true); ReadString(raw, ref next, true); }
        Require(next == raw.Length, "event-tail"); return e;
    }
    private static ulong ReadUnsigned(byte[] raw, int at, int size)
    {
        Require(at >= 0 && size > 0 && at <= raw.Length - size, "event-range");
        ulong value = 0; for (int i = 0; i < size; i++) value |= ((ulong)raw[at + i]) << (8 * i);
        return value;
    }
    private static string ReadString(byte[] raw, ref int at, bool unicode)
    {
        int start = at, step = unicode ? 2 : 1;
        for (int count = 0; count <= 32768; count++, at += step)
        {
            Require(at >= 0 && at <= raw.Length - step, "event-string-range");
            if (raw[at] == 0 && (!unicode || raw[at + 1] == 0))
            {
                string result = unicode ? Utf16.GetString(raw, start, at - start) : Utf8.GetString(raw, start, at - start);
                at += step; return result;
            }
        }
        throw new FailureException("event-string-cap");
    }

    private sealed class Child
    {
        private readonly Target target;
        private FileStream stdin, stdout, stderr;
        private Thread outWorker, errWorker;
        private readonly MemoryStream outBytes = new MemoryStream(), errBytes = new MemoryStream();
        private volatile bool outEnded, errEnded, firstLine, streamError;
        private bool inputClosed, exactOutput;
        private Child(Target target) { this.target = target; }
        internal static Child Start(Target target, string gateName)
        {
            Require((target.Role == "gated" && gateName == "gate-calibration.json") ||
                (target.Role == "fast" && gateName == null), "control-role");
            Child child = new Child(target); Children.Add(child);
            IntPtr inRead = IntPtr.Zero, inWrite = IntPtr.Zero, outRead = IntPtr.Zero,
                outWrite = IntPtr.Zero, errRead = IntPtr.Zero, errWrite = IntPtr.Zero;
            IntPtr attributes = IntPtr.Zero, handles = IntPtr.Zero, startup = IntPtr.Zero;
            bool attributesInitialized = false;
            Native.ProcessInformation process = new Native.ProcessInformation();
            try
            {
                Native.SecurityAttributes security = new Native.SecurityAttributes();
                security.Length = 24; security.Inherit = 1;
                Require(Native.CreatePipe(out inRead, out inWrite, ref security, 4096) &&
                    Native.CreatePipe(out outRead, out outWrite, ref security, 4096) &&
                    Native.CreatePipe(out errRead, out errWrite, ref security, 4096), "control-pipes");
                Require(Native.SetHandleInformation(inWrite, 1, 0) &&
                    Native.SetHandleInformation(outRead, 1, 0) &&
                    Native.SetHandleInformation(errRead, 1, 0), "control-parent-handles");
                IntPtr size = IntPtr.Zero;
                bool sized = Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                Require(!sized && Marshal.GetLastWin32Error() == 122 && size.ToInt64() > 0 &&
                    size.ToInt64() <= 65536, "control-attribute-size");
                attributes = Native.Allocate((int)size.ToInt64());
                Require(Native.InitializeProcThreadAttributeList(attributes, 1, 0, ref size), "control-attributes");
                attributesInitialized = true; handles = Native.Allocate(24);
                Marshal.WriteIntPtr(handles, 0, inRead); Marshal.WriteIntPtr(handles, 8, outWrite);
                Marshal.WriteIntPtr(handles, 16, errWrite);
                Require(Native.UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handles,
                    new IntPtr(24), IntPtr.Zero, IntPtr.Zero), "control-handle-list");
                startup = Native.Allocate(112); Marshal.WriteInt32(startup, 0, 112);
                Marshal.WriteInt32(startup, 60, 0x100);
                Marshal.WriteIntPtr(startup, 80, inRead); Marshal.WriteIntPtr(startup, 88, outWrite);
                Marshal.WriteIntPtr(startup, 96, errWrite); Marshal.WriteIntPtr(startup, 104, attributes);
                Require(Native.CreateProcess(target.Image, new StringBuilder(target.Command), IntPtr.Zero,
                    IntPtr.Zero, true, 0x08080404, IntPtr.Zero, Root, startup, out process), "control-create");
                // Creation returns the original process handle. Target owns it immediately, even on failure.
                lock (TargetLock)
                {
                    target.Handle = process.Process; process.Process = IntPtr.Zero;
                    target.HadHandle = true; target.CreationHandle = true; target.CreatedPid = process.ProcessId;
                    if (target.Pid != 0) Require(target.Pid == process.ProcessId, "creation-event-pid");
                    target.Pid = process.ProcessId;
                }
                long created = 0, exited, kernel, user; bool inJob;
                Require(Native.GetProcessId(target.Handle) == target.CreatedPid &&
                    SameImage(Native.Image(target.Handle), target.Image) &&
                    Native.GetProcessTimes(target.Handle, out created, out exited, out kernel, out user),
                    "control-creation-identity");
                target.CreationFileTime = created;
                Require(Native.IsProcessInJob(target.Handle, Job, out inJob) && inJob, "control-inherited-job");
                Native.Close(ref inRead); Native.Close(ref outWrite); Native.Close(ref errWrite);
                child.stdin = OwnStream(ref inWrite, FileAccess.Write);
                child.stdout = OwnStream(ref outRead, FileAccess.Read);
                child.stderr = OwnStream(ref errRead, FileAccess.Read);
                child.outWorker = new Thread(delegate() { child.Drain(child.stdout, child.outBytes, true); });
                child.errWorker = new Thread(delegate() { child.Drain(child.stderr, child.errBytes, false); });
                child.outWorker.IsBackground = true; child.errWorker.IsBackground = true;
                child.outWorker.Start(); child.errWorker.Start();
                Require(Native.ResumeThread(process.Thread) == 1, "control-resume");
                return child;
            }
            finally
            {
                Native.Close(ref process.Thread); Native.Close(ref process.Process);
                Native.Close(ref inRead); Native.Close(ref inWrite); Native.Close(ref outRead);
                Native.Close(ref outWrite); Native.Close(ref errRead); Native.Close(ref errWrite);
                if (attributesInitialized) Native.DeleteProcThreadAttributeList(attributes);
                Native.Free(ref attributes); Native.Free(ref handles); Native.Free(ref startup);
            }
        }
        private static FileStream OwnStream(ref IntPtr handle, FileAccess access)
        {
            SafeFileHandle safe = new SafeFileHandle(handle, true); handle = IntPtr.Zero;
            try { return new FileStream(safe, access, 4096, false); }
            catch { safe.Dispose(); throw; }
        }
        private void Drain(FileStream stream, MemoryStream bytes, bool output)
        {
            try
            {
                byte[] buffer = new byte[4096]; int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    Require(bytes.Length + count <= 524288, "control-output-cap");
                    long before = bytes.Length; bytes.Write(buffer, 0, count);
                    if (output && !firstLine)
                    {
                        int lf = Array.IndexOf(buffer, (byte)10, 0, count);
                        Require(lf >= 0 ? before + lf + 1 <= 4096 : bytes.Length <= 4096, "control-first-line-cap");
                        if (lf >= 0) firstLine = true;
                    }
                }
            }
            catch { streamError = true; Fail("control-stream"); }
            finally { if (output) outEnded = true; else errEnded = true; }
        }
        internal bool Signaled
        {
            get
            {
                Require(target.Handle != IntPtr.Zero, "control-handle");
                uint state = Native.WaitForSingleObject(target.Handle, 0);
                Require(state == 0 || state == 258, "control-wait");
                if (state == 0) target.HandleSignaled = true;
                return state == 0;
            }
        }
        internal bool StreamsEnded { get { return outEnded && errEnded; } }
        internal bool FirstLine { get { return firstLine; } }
        internal bool StreamError { get { return streamError; } }
        internal uint ExitCode
        {
            get { uint code = 0; Require(Signaled && Native.GetExitCodeProcess(target.Handle, out code),
                "control-exit"); return code; }
        }
        internal bool Matches(string line)
        {
            Require(StreamsEnded, "control-stream-live");
            exactOutput = !streamError && errBytes.Length == 0 &&
                Utf8.GetString(outBytes.ToArray()) == line;
            return exactOutput;
        }
        internal void CloseInput()
        {
            if (inputClosed) return;
            if (stdin != null) { stdin.Dispose(); stdin = null; }
            inputClosed = true;
        }
        internal void EnsureStopped(int milliseconds) { target.EnsureStopped(milliseconds); }
        internal void Close()
        {
            CloseInput();
            if (outWorker != null && outWorker.IsAlive)
                Require(outWorker.Join((int)Remaining(100)), "control-stdout-live");
            if (errWorker != null && errWorker.IsAlive)
                Require(errWorker.Join((int)Remaining(100)), "control-stderr-live");
            if (stdout != null) { stdout.Dispose(); stdout = null; }
            if (stderr != null) { stderr.Dispose(); stderr = null; }
        }
        internal void AddReceipt(Dictionary<string, string> record)
        {
            record.Add(target.Role + "InputClosed", Bool(inputClosed));
            record.Add(target.Role + "FirstLf", Bool(firstLine));
            record.Add(target.Role + "StreamsEnded", Bool(StreamsEnded));
            record.Add(target.Role + "StreamError", Bool(streamError));
            record.Add(target.Role + "ExactOutput", Bool(exactOutput));
            // A live reader's MemoryStream is not read concurrently, including on a failure path.
            record.Add(target.Role + "StdoutBytes", Num(outEnded ? outBytes.Length : -1));
            record.Add(target.Role + "StderrBytes", Num(errEnded ? errBytes.Length : -1));
        }
    }

    private sealed class FlatJson
    {
        private readonly string text;
        private int at;
        private FlatJson(byte[] raw)
        {
            Require(raw.Length <= 16384, "json-cap");
            foreach (byte b in raw) Require(b < 128, "json-encoding");
            text = Encoding.ASCII.GetString(raw);
        }
        internal static Dictionary<string, string> Parse(byte[] raw)
        {
            FlatJson p = new FlatJson(raw); Dictionary<string, string> result =
                new Dictionary<string, string>(StringComparer.Ordinal);
            p.White(); p.Take('{'); p.White();
            if (p.Peek() != '}') while (true)
            {
                string key = p.String(); p.White(); p.Take(':'); p.White(); string value = p.String();
                Require(key.Length > 0 && key.Length <= 64 && !result.ContainsKey(key) && result.Count < 128,
                    "json-duplicate-key-cap"); result.Add(key, value); p.White();
                if (p.Peek() != ',') break; p.at++; p.White();
            }
            p.Take('}'); p.White(); Require(p.at == p.text.Length, "json-tail"); return result;
        }
        private char Peek() { Require(at < text.Length, "json-short"); return text[at]; }
        private void Take(char c) { Require(Peek() == c, "json-token"); at++; }
        private void White()
        { while (at < text.Length && (text[at] == ' ' || text[at] == '\t' || text[at] == '\r' || text[at] == '\n')) at++; }
        private string String()
        {
            Take('"'); StringBuilder value = new StringBuilder();
            while (true)
            {
                char c = Peek(); at++;
                if (c == '"') return value.ToString();
                Require(c >= 32 && c <= 126, "json-string-character");
                if (c == '\\')
                {
                    c = Peek(); at++;
                    if (c == 'u')
                    {
                        Require(at <= text.Length - 4, "json-escape-short"); int n = 0;
                        for (int i = 0; i < 4; i++)
                        {
                            char h = text[at++]; int digit = h >= '0' && h <= '9' ? h - '0' :
                                h >= 'a' && h <= 'f' ? h - 'a' + 10 : h >= 'A' && h <= 'F' ? h - 'A' + 10 : -1;
                            Require(digit >= 0, "json-escape-hex"); n = 16 * n + digit;
                        }
                        Require(n >= 32 && n <= 126, "json-escape-character"); c = (char)n;
                    }
                    else Require(c == '"' || c == '\\' || c == '/', "json-escape");
                }
                value.Append(c); Require(value.Length <= 8192, "json-value-cap");
            }
        }
        internal static byte[] Encode(Dictionary<string, string> values)
        {
            List<string> keys = new List<string>(values.Keys); keys.Sort(StringComparer.Ordinal);
            StringBuilder output = new StringBuilder("{"); bool first = true;
            foreach (string key in keys)
            {
                if (!first) output.Append(','); first = false;
                Append(output, key); output.Append(':'); Append(output, values[key]);
            }
            output.Append("}\n"); return Encoding.ASCII.GetBytes(output.ToString());
        }
        private static void Append(StringBuilder output, string value)
        {
            Require(value != null, "json-null"); output.Append('"');
            foreach (char c in value)
            {
                Require(c >= 32 && c <= 126, "json-output-character");
                if (c == '"' || c == '\\') output.Append('\\'); output.Append(c);
            }
            output.Append('"');
        }
    }

    private static class Native
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void RecordCallback(IntPtr record);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate uint BufferCallback(IntPtr logfile);
        [StructLayout(LayoutKind.Sequential)] internal struct FileInformation
        {
            internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
                VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes
        { internal int Length; internal IntPtr Descriptor; internal int Inherit; }
        [StructLayout(LayoutKind.Sequential)] internal struct ProcessInformation
        { internal IntPtr Process, Thread; internal uint ProcessId, ThreadId; }
        internal static IntPtr Allocate(int size)
        {
            Require(size > 0 && size <= 65536, "native-allocation-cap");
            IntPtr value = Marshal.AllocHGlobal(size);
            for (int i = 0; i < size; i++) Marshal.WriteByte(value, i, 0); return value;
        }
        internal static void Free(ref IntPtr value)
        { if (value != IntPtr.Zero) { Marshal.FreeHGlobal(value); value = IntPtr.Zero; } }
        internal static void Close(ref IntPtr value)
        {
            if (value == IntPtr.Zero) return;
            if (!CloseHandle(value)) { ResourceUncertain = true; Fail("handle-close"); return; }
            value = IntPtr.Zero;
        }
        internal static string Image(IntPtr process)
        {
            StringBuilder value = new StringBuilder(32768); int length = value.Capacity;
            Require(QueryFullProcessImageName(process, 0, value, ref length) && length > 0 && length < value.Capacity,
                "process-image"); return value.ToString();
        }
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "OpenJobObjectW", SetLastError = true)]
        internal static extern IntPtr OpenJobObject(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryDosDeviceW", SetLastError = true)]
        internal static extern uint QueryDosDevice(string name, StringBuilder target, int length);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateFileW", SetLastError = true)]
        internal static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(IntPtr file, out FileInformation information);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateEventW", SetLastError = true)]
        internal static extern IntPtr CreateEvent(IntPtr security, [MarshalAs(UnmanagedType.Bool)] bool manual,
            [MarshalAs(UnmanagedType.Bool)] bool initial, string name);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DeviceIoControl(IntPtr file, uint code, IntPtr input, uint inputLength,
            IntPtr output, uint outputLength, IntPtr bytesReturned, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetOverlappedResultEx(IntPtr file, IntPtr overlapped, out uint transferred,
            uint milliseconds, [MarshalAs(UnmanagedType.Bool)] bool alertable);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint GetProcessId(IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(IntPtr process, out uint exit);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(IntPtr process, uint exit);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder image, ref int length);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes security, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
            IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);
        [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcess(string application, StringBuilder command, IntPtr processSecurity,
            IntPtr threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, IntPtr environment,
            string directory, IntPtr startup, out ProcessInformation process);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(IntPtr thread);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "StartTraceW")]
        internal static extern uint StartTrace(out ulong session, string name, IntPtr properties);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "ControlTraceW")]
        internal static extern uint ControlTrace(ulong session, string name, IntPtr properties, uint control);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "OpenTraceW", SetLastError = true)]
        internal static extern ulong OpenTrace(IntPtr logfile);
        [DllImport("advapi32.dll")] internal static extern uint ProcessTrace(ref ulong handles, uint count, IntPtr start, IntPtr end);
        [DllImport("advapi32.dll")] internal static extern uint CloseTrace(ulong consumer);
    }
}
