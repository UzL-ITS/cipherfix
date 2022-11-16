namespace StaticInstrumentation;

public class Constants
{
    public const long ManagementObjectAddress = 0x700000000000;
    public const int ManagementObjectInt3HtListOffset = 0;
    public const int ManagementObjectInt3HtListCount = 16;
    public const int ManagementObjectHeaderAddrListOffset = ManagementObjectInt3HtListOffset + 8 * ManagementObjectInt3HtListCount;
    public const int ManagementObjectHeaderAddrListCount = 16;
    public const int ManagementObjectAllocTrackerOffset = ManagementObjectHeaderAddrListOffset + 8 * ManagementObjectHeaderAddrListCount;
    public const int ManagementObjectAllocTrackerSize = 8;
}