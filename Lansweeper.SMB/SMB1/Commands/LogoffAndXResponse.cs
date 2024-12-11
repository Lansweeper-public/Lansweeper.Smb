using Lansweeper.Smb.SMB1.Enums;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_LOGOFF_ANDX Response
///     
/// SMB_Parameters
/// {
///   UCHAR WordCount;
///   Words
///   {
///     UCHAR AndXCommand;
///     UCHAR AndXReserved;
///     USHORT AndXOffset;
///   }
/// }
/// SMB_Data
/// {
///   USHORT ByteCount; // must be 0x0000
/// }
/// </summary>
public class LogoffAndXResponse : SmbAndXCommand
{
    public const int ParametersLength = 4;

    public LogoffAndXResponse() { }

    public LogoffAndXResponse(ReadOnlySpan<byte> buffer) : base(buffer) { }

    public override CommandName CommandName => CommandName.SMB_COM_LOGOFF_ANDX;

    public override byte[] GetBytes(bool isUnicode)
    {
        SMBParameters = new byte[ParametersLength];
        return base.GetBytes(isUnicode);
    }
}