// Separate credential-free calibration executable. No activation is supplied.
#nullable enable
using System;
using System.IO;
using System.Text.RegularExpressions;

namespace ConfidentialWslCalibration;
internal static class CalibrationSubjectProgram
{
    private static readonly bool ExecutionAdmitted = false;
    public static int Main(string[] args)
    {
        if (!ExecutionAdmitted) return 125;
        try
        {
            if (args.Length != 2 || !Regex.IsMatch(args[1], "\\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\\z")) return 1;
            if (args[0] == "--calibration-fast") return 0;
            if (args[0] != "--calibration-gated") return 1;
            // One blocking read, no write. The original observer owns the sole
            // writer; the supervisor's finite inherited Job bounds this child.
            using Stream input = Console.OpenStandardInput();
            return input.ReadByte() == -1 ? 0 : 1;
        }
        catch { return 1; }
    }
}
