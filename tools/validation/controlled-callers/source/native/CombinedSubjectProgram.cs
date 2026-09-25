#nullable enable
namespace ConfidentialNativeCaller;
internal static class CombinedSubjectProgram
{
    private static readonly bool ExecutionAdmitted=false;
    public static int Main(string[] args)
    {
        if(!ExecutionAdmitted)return 125;
        if(args.Length>0 && args[0] is "--calibration-fast" or "--calibration-gated")
            return ConfidentialWslCalibration.CalibrationSubjectProgram.Main(args);
        if(System.Array.IndexOf(args,"--synthetic-direct")>=0)return DirectSyntheticSubjectProgram.Main(args);
        return SyntheticSubjectProgram.Main(args);
    }
}
