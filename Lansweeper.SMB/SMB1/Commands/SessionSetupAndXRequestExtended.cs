using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_SESSION_SETUP_ANDX Extended Request
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
///     USHORT SecurityBlobLength;
///     ULONG Reserved;
///     ULONG Capabilities;
///   }
/// }
/// SMB_Data
/// {
///   USHORT ByteCount;
///   Bytes
///   {
///     UCHAR SecurityBlob[SecurityBlobLength];
///     SMB_STRING NativeOS[];
///     SMB_STRING NativeLanMan[];
///   }
/// }
/// </summary>
public class SessionSetupAndXRequestExtended : SmbAndXCommand
{
    public const int ParametersLength = 24;


    // Parameters:
    public ushort MaxBufferSize { get; set; }
    public ushort MaxMpxCount { get; set; }
    public ushort VcNumber { get; set; }
    public uint SessionKey { get; set; }
    private ushort SecurityBlobLength { get; set; }
    public uint Reserved { get; set; }
    public Capabilities Capabilities { get; set; }


    // Data:
    public byte[] SecurityBlob { get; set; }
    // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string NativeOS { get; set; }
    // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
    public string NativeLanMan { get; set; }

    public SessionSetupAndXRequestExtended()
    {
        NativeOS = string.Empty;
        NativeLanMan = string.Empty;
        SecurityBlob = [];
    }

    public SessionSetupAndXRequestExtended(ReadOnlySpan<byte> buffer, bool isUnicode) : base(buffer)
    {
        ReadOnlySpan<byte> parameters = SMBParameters.AsSpan(4);
        MaxBufferSize = LittleEndianReader.ReadUInt16(ref parameters);
        MaxMpxCount = LittleEndianReader.ReadUInt16(ref parameters);
        VcNumber = LittleEndianReader.ReadUInt16(ref parameters);
        SessionKey = LittleEndianReader.ReadUInt32(ref parameters);
        SecurityBlobLength = LittleEndianReader.ReadUInt16(ref parameters);
        Reserved = LittleEndianReader.ReadUInt32(ref parameters);
        Capabilities = (Capabilities)LittleEndianReader.ReadUInt32(ref parameters);

        ReadOnlySpan<byte> data = SMBData;
        SecurityBlob = ByteReader.ReadBytes(ref data, SecurityBlobLength);

        if (isUnicode)
        {
            // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
            // Note: SMBData starts at an odd offset.
            var padding = (1 + SecurityBlobLength) % 2;
            data = data[padding..];
        }

        NativeOS = Smb1Helper.ReadSMBString(ref data, isUnicode);
        NativeLanMan = Smb1Helper.ReadSMBString(ref data, isUnicode);
    }

    public override CommandName CommandName => CommandName.SMB_COM_SESSION_SETUP_ANDX;

    public override byte[] GetBytes(bool isUnicode)
    {
        Capabilities |= Capabilities.ExtendedSecurity;
        SecurityBlobLength = (ushort)SecurityBlob.Length;

        SMBParameters = new byte[ParametersLength];
        Span<byte> parameters = SMBParameters.AsSpan(4);
        LittleEndianWriter.WriteUInt16(ref parameters, MaxBufferSize);
        LittleEndianWriter.WriteUInt16(ref parameters, MaxMpxCount);
        LittleEndianWriter.WriteUInt16(ref parameters, VcNumber);
        LittleEndianWriter.WriteUInt32(ref parameters, SessionKey);
        LittleEndianWriter.WriteUInt16(ref parameters, SecurityBlobLength);
        LittleEndianWriter.WriteUInt32(ref parameters, Reserved);
        LittleEndianWriter.WriteUInt32(ref parameters, (uint)Capabilities);

        var padding = 0;
        if (isUnicode)
        {
            padding = (1 + SecurityBlobLength) % 2;
            SMBData =
                new byte[SecurityBlob.Length + padding + (NativeOS.Length + 1) * 2 + (NativeLanMan.Length + 1) * 2];
        }
        else
        {
            SMBData = new byte[SecurityBlob.Length + NativeOS.Length + 1 + NativeLanMan.Length + 1];
        }

        Span<byte> data = SMBData;
        ByteWriter.WriteBytes(ref data, SecurityBlob);
        data = data[padding..];
        Smb1Helper.WriteSMBString(ref data, isUnicode, NativeOS);
        Smb1Helper.WriteSMBString(ref data, isUnicode, NativeLanMan);

        return base.GetBytes(isUnicode);
    }
}