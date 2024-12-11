using System.Buffers.Binary;

namespace Lansweeper.Smb.Authentication.NTLM;

/// <summary>
///     [MS-NLMP] 2.2.2.10 - VERSION
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   | MajorVersion  | MinorVersion  |           Build               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                      Reserved                 |  RevisionCurr |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 
/// </summary>
public class NtlmVersion
{
    public const int Length = 8;
    public const byte NTLMSSP_REVISION_W2K3 = 0x0F;


    public byte ProductMajorVersion { get; set; }
    public byte ProductMinorVersion { get; set; }
    public ushort ProductBuild { get; set; }
    // Reserved - 3 bytes
    public byte NTLMRevisionCurrent { get; set; }

    public NtlmVersion(byte majorVersion, byte minorVersion, ushort build, byte ntlmRevisionCurrent)
    {
        ProductMajorVersion = majorVersion;
        ProductMinorVersion = minorVersion;
        ProductBuild = build;
        NTLMRevisionCurrent = ntlmRevisionCurrent;
    }

    public NtlmVersion(ReadOnlySpan<byte> buffer)
    {
        ProductMajorVersion = buffer[0];
        ProductMinorVersion = buffer[1];
        ProductBuild = BinaryPrimitives.ReadUInt16LittleEndian(buffer[2..4]);
        NTLMRevisionCurrent = buffer[7];
    }


    public static NtlmVersion WindowsXP => new(5, 1, 2600, NTLMSSP_REVISION_W2K3);
    public static NtlmVersion Server2003 => new(5, 2, 3790, NTLMSSP_REVISION_W2K3);
    public static NtlmVersion Unset { get; } = new(0, 0, 0, 0); // MUST be set to all zero

    public void WriteBytes(Span<byte> buffer)
    {
        buffer[0] = ProductMajorVersion;
        buffer[1] = ProductMinorVersion;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer[2..4], ProductBuild);
        buffer[4..7].Clear(); // Reserved
        buffer[7] = NTLMRevisionCurrent;
    }

    public override string ToString()
    {
        return $"{ProductMajorVersion}.{ProductMinorVersion}.{ProductBuild}";
    }
}