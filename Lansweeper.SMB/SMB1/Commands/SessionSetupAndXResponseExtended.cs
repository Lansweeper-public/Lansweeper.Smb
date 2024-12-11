using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_SESSION_SETUP_ANDX Response, NT LAN Manager dialect, Extended Security response
///     
/// SMB_Parameters
/// {
///   UCHAR WordCount;
///   Words
///   {
///     UCHAR AndXCommand;
///     UCHAR AndXReserved;
///     USHORT AndXOffset;
///     USHORT Action;
///     USHORT SecurityBlobLength;
///   }
/// }
/// SMB_Data
/// {
///   USHORT ByteCount;
///   Bytes
///   {
///     UCHAR SecurityBlob[SecurityBlobLength] ;
///     UCHAR Pad[];
///     SMB_STRING NativeOS[];
///     SMB_STRING NativeLanMan[];
///   }
/// }
/// </summary>
public class SessionSetupAndXResponseExtended : SmbAndXCommand
{
    public const int ParametersLength = 8;

    // Parameters:
    public SessionSetupAction Action { get; set; }
    private ushort SecurityBlobLength { get; }


    // Data:
    public byte[] SecurityBlob { get; set; }
    // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string NativeOS { get; set; }
    // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string NativeLanMan { get; set; }
    /// <remarks>
    /// Not part of the specification for responses with extended security, but is sometimes found in the response.
    /// </remarks>
    // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string PrimaryDomain { get; set; }


    public SessionSetupAndXResponseExtended()
    {
        SecurityBlob = [];
        NativeOS = string.Empty;
        NativeLanMan = string.Empty;
        PrimaryDomain = string.Empty;
    }

    public SessionSetupAndXResponseExtended(ReadOnlySpan<byte> buffer, bool isUnicode) : base(buffer)
    {
        ReadOnlySpan<byte> parameters = SMBParameters.AsSpan(4);
        Action = (SessionSetupAction)LittleEndianReader.ReadUInt16(ref parameters);
        SecurityBlobLength = LittleEndianReader.ReadUInt16(ref parameters);
        SecurityBlob = SMBData.AsSpan(0, SecurityBlobLength).ToArray();

        int dataOffset = SecurityBlobLength;
        if (isUnicode)
        {
            // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
            // Note: SMBData starts at an odd offset.
            int padding = (1 + SecurityBlobLength) % 2;
            dataOffset += padding;
        }

        // Workaround for a single terminating null byte
        if (isUnicode && (SMBData.Length - dataOffset) % 2 == 1)
        {
            SMBData = ByteUtils.Concatenate(SMBData, new byte[1]);
        }

        ReadOnlySpan<byte> data = SMBData.AsSpan(dataOffset);
        NativeOS = Smb1Helper.ReadSMBString(ref data, isUnicode);
        NativeLanMan = Smb1Helper.ReadSMBString(ref data, isUnicode);

        PrimaryDomain = data.ContainsAnyExcept((byte)0x00) 
            ? Smb1Helper.ReadSMBString(ref data, isUnicode)
            : string.Empty;

        // there might be a some junk null bytes at the end of the data
    }

    public override CommandName CommandName => CommandName.SMB_COM_SESSION_SETUP_ANDX;

    public override byte[] GetBytes(bool isUnicode)
    {
        var securityBlobLength = (ushort)SecurityBlob.Length;

        SMBParameters = new byte[ParametersLength];
        Span<byte> parameters = SMBParameters.AsSpan(4);
        LittleEndianWriter.WriteUInt16(ref parameters, (ushort)Action);
        LittleEndianWriter.WriteUInt16(ref parameters, securityBlobLength);

        var padding = 0;
        if (isUnicode)
        {
            // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
            // Note: SMBData starts at an odd offset.
            padding = (1 + securityBlobLength) % 2;
            SMBData = new byte[SecurityBlob.Length + padding + NativeOS.Length * 2 + NativeLanMan.Length * 2 + 4];
        }
        else
        {
            SMBData = new byte[SecurityBlob.Length + NativeOS.Length + NativeLanMan.Length + 2];
        }

        Span<byte> data = SMBData;
        ByteWriter.WriteBytes(ref data, SecurityBlob);
        data = data[padding..];
        Smb1Helper.WriteSMBString(ref data, isUnicode, NativeOS);
        Smb1Helper.WriteSMBString(ref data, isUnicode, NativeLanMan);

        return base.GetBytes(isUnicode);
    }
}