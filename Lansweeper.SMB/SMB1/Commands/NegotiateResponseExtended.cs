using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_NEGOTIATE Response, NT LAN Manager dialect, Extended Security response
///     For NT LAN Manager dialect, No Extended Security response, see <see cref="NegotiateResponse"/>
///     
/// SMB_Parameters
/// {
///   UCHAR WordCount;
///   Words
///   {
///     USHORT DialectIndex;
///     UCHAR SecurityMode;
///     USHORT MaxMpxCount;
///     USHORT MaxNumberVcs;
///     ULONG MaxBufferSize;
///     ULONG MaxRawSize;
///     ULONG SessionKey;
///     ULONG Capabilities;
///     FILETIME SystemTime;
///     SHORT ServerTimeZone;
///     UCHAR ChallengeLength;
///   }
/// }
/// SMB_Data
/// {
///   USHORT ByteCount;
///   Bytes
///   {
///     GUID ServerGUID;
///     UCHAR SecurityBlob[];
///   }
/// }
/// </summary>
/// <remarks>
///     Capabilities.ExtendedSecurity should be set to true
/// </remarks>
public class NegotiateResponseExtended : Smb1Command
{
    public const int ParametersLength = 34;




    // Parameters:
    public ushort DialectIndex { get; set; }
    public SecurityMode SecurityMode { get; set; }
    public ushort MaxMpxCount { get; set; }
    public ushort MaxNumberVcs { get; set; }
    public uint MaxBufferSize { get; set; }
    public uint MaxRawSize { get; set; }
    public uint SessionKey { get; set; }
    public Capabilities Capabilities { get; set; }
    public DateTime SystemTime { get; set; }
    public short ServerTimeZone { get; set; }

    private byte _challengeLength = 0;

    /// <remarks>MUST be set to 0 with Extended Security</remarks>
    private byte ChallengeLength
    {
        get => _challengeLength;
        set
        {
            if (value != 0)
            {
                throw new InvalidDataException("ChallengeLength MUST be set to 0 for SMB Negotiate Response with Extended Security set");
            }
            _challengeLength = value;
        }
    }

    // Data:
    public Guid ServerGuid { get; set; }
    /// <remarks>
    /// [MS-SMB] 3.3.5.2: The server can leave SecurityBlob empty if not configured to send GSS token.
    /// </summary>
    public byte[] SecurityBlob { get; set; }

    public NegotiateResponseExtended()
    {
        SecurityBlob = [];
    }

    public NegotiateResponseExtended(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        ReadOnlySpan<byte> smbParametersSpan = SMBParameters;

        DialectIndex = LittleEndianReader.ReadUInt16(ref smbParametersSpan);
        SecurityMode = (SecurityMode)ByteReader.ReadByte(ref smbParametersSpan);
        MaxMpxCount = LittleEndianReader.ReadUInt16(ref smbParametersSpan);
        MaxNumberVcs = LittleEndianReader.ReadUInt16(ref smbParametersSpan);
        MaxBufferSize = LittleEndianReader.ReadUInt32(ref smbParametersSpan);
        MaxRawSize = LittleEndianReader.ReadUInt32(ref smbParametersSpan);
        SessionKey = LittleEndianReader.ReadUInt32(ref smbParametersSpan);
        Capabilities = (Capabilities)LittleEndianReader.ReadUInt32(ref smbParametersSpan);
        SystemTime = LittleEndianReader.ReadFileTime(ref smbParametersSpan);
        ServerTimeZone = LittleEndianReader.ReadInt16(ref smbParametersSpan);
        ChallengeLength = ByteReader.ReadByte(ref smbParametersSpan);

        ReadOnlySpan<byte> dataSpan = SMBData;
        ServerGuid = BigEndianReader.ReadGuid(ref dataSpan); // appears to be big-endian, unlike SMB2
        SecurityBlob = dataSpan.ToArray();
    }

    public override CommandName CommandName => CommandName.SMB_COM_NEGOTIATE;

    public override byte[] GetBytes(bool isUnicode)
    {
        ChallengeLength = 0;

        SMBParameters = new byte[ParametersLength];
        Span<byte> parameters = SMBParameters;
        LittleEndianWriter.WriteUInt16(ref parameters, DialectIndex);
        ByteWriter.WriteByte(ref parameters, (byte)SecurityMode);
        LittleEndianWriter.WriteUInt16(ref parameters, MaxMpxCount);
        LittleEndianWriter.WriteUInt16(ref parameters, MaxNumberVcs);
        LittleEndianWriter.WriteUInt32(ref parameters, MaxBufferSize);
        LittleEndianWriter.WriteUInt32(ref parameters, MaxRawSize);
        LittleEndianWriter.WriteUInt32(ref parameters, SessionKey);
        LittleEndianWriter.WriteUInt32(ref parameters, (uint)Capabilities);
        LittleEndianWriter.WriteFileTime(ref parameters, SystemTime);
        LittleEndianWriter.WriteInt16(ref parameters, ServerTimeZone);
        ByteWriter.WriteByte(ref parameters, ChallengeLength);

        SMBData = new byte[16 + SecurityBlob.Length];
        Span<byte> data = SMBData;
        BigEndianWriter.WriteGuid(ref data, ServerGuid); // appears to be big-endian, unlike SMB2
        ByteWriter.WriteBytes(ref data, SecurityBlob);

        return base.GetBytes(isUnicode);
    }

}