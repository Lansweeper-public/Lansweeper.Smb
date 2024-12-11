using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_SESSION_SETUP_ANDX Response
///     
/// SMB_Parameters
///  {
///    UCHAR WordCount;
///    Words
///    {
///      UCHAR AndXCommand;
///      UCHAR AndXReserved;
///      USHORT AndXOffset;
///      USHORT Action;
///    }
///  }
/// SMB_Data
///  {
///    USHORT ByteCount;
///    Bytes
///    {
///      UCHAR Pad[] ;
///      SMB_STRING NativeOS[];
///      SMB_STRING NativeLanMan[];
///      SMB_STRING PrimaryDomain[];
///    }
///  }
/// </summary>
public class SessionSetupAndXResponse : SmbAndXCommand
{
    public const int ParametersLength = 6;

    // Parameters:
    public SessionSetupAction Action { get; set; }

    // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string NativeLanMan { get; set; }

    // Data:
    // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string NativeOS { get; set; }

    // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string PrimaryDomain { get; set; }

    public SessionSetupAndXResponse()
    {
        NativeOS = string.Empty;
        NativeLanMan = string.Empty;
        PrimaryDomain = string.Empty;
    }

    public SessionSetupAndXResponse(ReadOnlySpan<byte> buffer, bool isUnicode) : base(buffer)
    {
        ReadOnlySpan<byte> parameters = SMBParameters.AsSpan(4);
        Action = (SessionSetupAction)LittleEndianReader.ReadUInt16(ref parameters);

        // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
        // Note: SMBData starts at an odd offset.
        int dataOffset = isUnicode ? 1 : 0;

        // Workaround for a single terminating null byte
        if (isUnicode && (SMBData.Length - dataOffset) % 2 == 1)
        {
            SMBData = [.. SMBData, 0x00];
        }

        ReadOnlySpan<byte> data = SMBData.AsSpan(dataOffset);
        NativeOS = Smb1Helper.ReadSMBString(ref data, isUnicode);
        NativeLanMan = Smb1Helper.ReadSMBString(ref data, isUnicode);
        PrimaryDomain = Smb1Helper.ReadSMBString(ref data, isUnicode);

        // there might be a some junk null bytes at the end of the data
    }

    public override CommandName CommandName => CommandName.SMB_COM_SESSION_SETUP_ANDX;


    public override byte[] GetBytes(bool isUnicode)
    { 
        SMBParameters = new byte[ParametersLength];
        Span<byte> parameters = SMBParameters.AsSpan(4);
        LittleEndianWriter.WriteUInt16(ref parameters, (ushort)Action);

        var padding = 0;
        if (isUnicode)
        {
            padding = 1;
            SMBData = new byte[padding + NativeOS.Length * 2 + NativeLanMan.Length * 2 + PrimaryDomain.Length * 2 + 6];
        }
        else
        {
            SMBData = new byte[NativeOS.Length + NativeLanMan.Length + PrimaryDomain.Length + 3];
        }

        Span<byte> data = SMBData.AsSpan(padding);
        Smb1Helper.WriteSMBString(ref data, isUnicode, NativeOS);
        Smb1Helper.WriteSMBString(ref data, isUnicode, NativeLanMan);
        Smb1Helper.WriteSMBString(ref data, isUnicode, PrimaryDomain);

        return base.GetBytes(isUnicode);
    }

}