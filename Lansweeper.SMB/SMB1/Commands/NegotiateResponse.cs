using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_NEGOTIATE Response, NT LAN Manager dialect, No Extended Security response
///     For Extended Security response, see <see cref="NegotiateResponseExtended"/>
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
///     UCHAR Challenge[] ;
///     SMB_STRING DomainName[];
///   }
/// }
/// </summary>
/// <remarks>
///     Capabilities.ExtendedSecurity should be set to false
/// </remarks>
public class NegotiateResponse : Smb1Command
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
    private byte ChallengeLength { get; set; }

    // Data:
    public byte[] Challenge { get; set; }

    /// <remarks>
    /// SMB_STRING
    /// If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header
    /// </remarks>
    public string DomainName { get; set; }

    /// <remarks>
    /// SMB_STRING
    /// this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header
    /// </remarks>
    public string ServerName { get; set; } // not used in NT LM 0.12 dialect

    public NegotiateResponse()
    {
        Challenge = [];
        DomainName = string.Empty;
        ServerName = string.Empty;
    }

    public NegotiateResponse(ReadOnlySpan<byte> buffer, bool isUnicode) : base(buffer)
    {
        ReadOnlySpan<byte> parameters = SMBParameters;

        DialectIndex = LittleEndianReader.ReadUInt16(ref parameters);
        SecurityMode = (SecurityMode)ByteReader.ReadByte(ref parameters);
        MaxMpxCount = LittleEndianReader.ReadUInt16(ref parameters);
        MaxNumberVcs = LittleEndianReader.ReadUInt16(ref parameters);
        MaxBufferSize = LittleEndianReader.ReadUInt32(ref parameters);
        MaxRawSize = LittleEndianReader.ReadUInt32(ref parameters);
        SessionKey = LittleEndianReader.ReadUInt32(ref parameters);
        Capabilities = (Capabilities)LittleEndianReader.ReadUInt32(ref parameters);
        SystemTime = LittleEndianReader.ReadFileTime(ref parameters);
        ServerTimeZone = LittleEndianReader.ReadInt16(ref parameters);
        ChallengeLength = ByteReader.ReadByte(ref parameters);

        ReadOnlySpan<byte> data = SMBData;
        Challenge = ByteReader.ReadBytes(ref data, ChallengeLength);
        // [MS-CIFS] <90> Padding is not added before DomainName
        // DomainName and ServerName are always in Unicode
        DomainName = Smb1Helper.ReadSMBString(ref data, true);
        ServerName = data.ContainsAnyExcept((byte)0x00)
            ? Smb1Helper.ReadSMBString(ref data, true)
            : string.Empty;
    }

    public override CommandName CommandName => CommandName.SMB_COM_NEGOTIATE;

    public override byte[] GetBytes(bool isUnicode)
    {
        ChallengeLength = (byte)Challenge.Length;

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

        // [MS-CIFS] <90> Padding is not added before DomainName
        // DomainName and ServerName are always in Unicode
        SMBData = new byte[Challenge.Length + (DomainName.Length + 1) * 2 + (ServerName.Length + 1) * 2];
        Span<byte> data = SMBData;
        ByteWriter.WriteBytes(ref data, Challenge);
        Smb1Helper.WriteSMBString(ref data, true, DomainName);
        Smb1Helper.WriteSMBString(ref data, true, ServerName);

        return base.GetBytes(isUnicode);
    }

}