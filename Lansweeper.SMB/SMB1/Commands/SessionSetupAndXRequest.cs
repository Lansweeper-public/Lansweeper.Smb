using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_SESSION_SETUP_ANDX Request
///     see CIFS 2.2.4.53.1 Request
///     
/// SMB_Parameters
/// {
///   UCHAR WordCount;
///   Words
///   {
///     UCHAR AndXCommand;
///     UCHAR AndXReserved;
///     USHORT AndXOffset;
///     USHORT MaxBufferSize;
///     USHORT MaxMpxCount;
///     USHORT VcNumber;
///     ULONG SessionKey;
///     USHORT OEMPasswordLen;
///     USHORT UnicodePasswordLen;
///     ULONG Reserved;
///     ULONG Capabilities;
///   }
/// }
/// SMB_Data
///  {
///    USHORT ByteCount;
///    Bytes
///    {
///      UCHAR OEMPassword[] ;
///      UCHAR UnicodePassword[];
///      UCHAR Pad[];
///      SMB_STRING AccountName[];
///      SMB_STRING PrimaryDomain[];
///      SMB_STRING NativeOS[];
///      SMB_STRING NativeLanMan[];
///    }
/// }
///
/// </summary>
public class SessionSetupAndXRequest : SmbAndXCommand
{
    public const int ParametersLength = 26;

    // Parameters:
    public ushort MaxBufferSize { get; set; }
    public ushort MaxMpxCount { get; set; }
    public ushort VcNumber { get; set; }
    public uint SessionKey { get; set; }
    private ushort OEMPasswordLength { get; set; }
    private ushort UnicodePasswordLength { get; set; }
    public uint Reserved { get; set; }
    public Capabilities Capabilities { get; set; }

    // Data:
    public byte[] OEMPassword { get; set; }
    public byte[] UnicodePassword { get; set; }
    // Padding
    // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string AccountName { get; set; }
    // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string PrimaryDomain { get; set; }
    // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string NativeOS { get; set; }
    // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string NativeLanMan { get; set; }



    public SessionSetupAndXRequest()
    {
        AccountName = string.Empty;
        PrimaryDomain = string.Empty;
        NativeOS = string.Empty;
        NativeLanMan = string.Empty;
        OEMPassword = [];
        UnicodePassword = [];
    }

    public SessionSetupAndXRequest(ReadOnlySpan<byte> buffer, bool isUnicode) : base(buffer)
    {
        ReadOnlySpan<byte> parameters = SMBParameters.AsSpan(4);
        MaxBufferSize = LittleEndianReader.ReadUInt16(ref parameters);
        MaxMpxCount = LittleEndianReader.ReadUInt16(ref parameters);
        VcNumber = LittleEndianReader.ReadUInt16(ref parameters);
        SessionKey = LittleEndianReader.ReadUInt32(ref parameters);
        OEMPasswordLength = LittleEndianReader.ReadUInt16(ref parameters);
        UnicodePasswordLength = LittleEndianReader.ReadUInt16(ref parameters);
        Reserved = LittleEndianReader.ReadUInt32(ref parameters);
        Capabilities = (Capabilities)LittleEndianReader.ReadUInt32(ref parameters);

        ReadOnlySpan<byte> data = SMBData;
        OEMPassword = ByteReader.ReadBytes(ref data, OEMPasswordLength);
        UnicodePassword = ByteReader.ReadBytes(ref data, UnicodePasswordLength);

        if (isUnicode)
        {
            // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
            // Note: SMBData starts at an odd offset.
            var padding = (1 + OEMPasswordLength + UnicodePasswordLength) % 2;
            data = data[padding..];
        }

        AccountName = Smb1Helper.ReadSMBString(ref data, isUnicode);
        PrimaryDomain = Smb1Helper.ReadSMBString(ref data, isUnicode);
        NativeOS = Smb1Helper.ReadSMBString(ref data, isUnicode);
        NativeLanMan = Smb1Helper.ReadSMBString(ref data, isUnicode);
    }

    public override CommandName CommandName => CommandName.SMB_COM_SESSION_SETUP_ANDX;

    public override byte[] GetBytes(bool isUnicode)
    {
        // ensure values
        Capabilities &= ~Capabilities.ExtendedSecurity;
        OEMPasswordLength = (ushort)OEMPassword.Length;
        UnicodePasswordLength = (ushort)UnicodePassword.Length;

        // parameters
        SMBParameters = new byte[ParametersLength];
        Span<byte> parameters = SMBParameters.AsSpan(4);
        LittleEndianWriter.WriteUInt16(ref parameters, MaxBufferSize);
        LittleEndianWriter.WriteUInt16(ref parameters, MaxMpxCount);
        LittleEndianWriter.WriteUInt16(ref parameters, VcNumber);
        LittleEndianWriter.WriteUInt32(ref parameters, SessionKey);
        LittleEndianWriter.WriteUInt16(ref parameters, OEMPasswordLength);
        LittleEndianWriter.WriteUInt16(ref parameters, UnicodePasswordLength);
        LittleEndianWriter.WriteUInt32(ref parameters, Reserved);
        LittleEndianWriter.WriteUInt32(ref parameters, (uint)Capabilities);

        // data
        var padding = 0;
        if (isUnicode)
        {
            padding = (1 + OEMPasswordLength + UnicodePasswordLength) % 2;
            SMBData = new byte[OEMPassword.Length + UnicodePassword.Length + padding + (AccountName.Length + 1) * 2 +
                               (PrimaryDomain.Length + 1) * 2 + (NativeOS.Length + 1) * 2 +
                               (NativeLanMan.Length + 1) * 2];
        }
        else
        {
            SMBData = new byte[OEMPassword.Length + UnicodePassword.Length + AccountName.Length + 1 +
                               PrimaryDomain.Length + 1 + NativeOS.Length + 1 + NativeLanMan.Length + 1];
        }

        Span<byte> data = SMBData;
        ByteWriter.WriteBytes(ref data, OEMPassword);
        ByteWriter.WriteBytes(ref data, UnicodePassword);
        data = data[padding..];
        Smb1Helper.WriteSMBString(ref data, isUnicode, AccountName);
        Smb1Helper.WriteSMBString(ref data, isUnicode, PrimaryDomain);
        Smb1Helper.WriteSMBString(ref data, isUnicode, NativeOS);
        Smb1Helper.WriteSMBString(ref data, isUnicode, NativeLanMan);

        return base.GetBytes(isUnicode);
    }
}