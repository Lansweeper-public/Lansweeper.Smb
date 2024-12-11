using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_NEGOTIATE Response
/// </summary>
public class NegotiateResponseNotSupported : Smb1Command
{
    public const int ParametersLength = 2;
    public const ushort DialectsNotSupported = 0xFFFF;

    public NegotiateResponseNotSupported() { }

    public NegotiateResponseNotSupported(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        throw new NotImplementedException();
    }

    public override CommandName CommandName => CommandName.SMB_COM_NEGOTIATE;

    public override byte[] GetBytes(bool isUnicode)
    {
        SMBParameters = new byte[ParametersLength];
        LittleEndianWriter.WriteUInt16(SMBParameters, DialectsNotSupported);

        SMBData = [];

        return base.GetBytes(isUnicode);
    }
}