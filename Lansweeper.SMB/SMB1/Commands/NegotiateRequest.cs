using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     SMB_COM_NEGOTIATE Request
///     
/// SMB_Parameters
/// {
///   UCHAR WordCount;
/// }
/// SMB_Data
/// {
///   USHORT ByteCount;
///   Bytes
///   {
///     UCHAR Dialects[] ;
///   }
/// }
/// </summary>
public class NegotiateRequest : Smb1Command
{
    public const int SupportedBufferFormat = 0x02;

    // Data:
    public List<string> Dialects { get; } = [];

    public NegotiateRequest() { }

    public NegotiateRequest(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        ReadOnlySpan<byte> dataSpan = SMBData;
        while (!dataSpan.IsEmpty)
        {
            var bufferFormat = ByteReader.ReadByte(ref dataSpan);
            if (bufferFormat != SupportedBufferFormat) throw new InvalidDataException("Unsupported Buffer Format");
            var dialect = ByteReader.ReadNullTerminatedAnsiString(ref dataSpan);
            Dialects.Add(dialect);
        }
    }

    public override CommandName CommandName => CommandName.SMB_COM_NEGOTIATE;

    public override byte[] GetBytes(bool isUnicode)
    {
        var length = 0;
        foreach (var dialect in Dialects) length += 1 + dialect.Length + 1;

        SMBParameters = [];
        SMBData = new byte[length];
        Span<byte> data = SMBData;
        foreach (var dialect in Dialects)
        {
            ByteWriter.WriteByte(ref data, 0x02);
            ByteWriter.WriteAnsiString(ref data, dialect);
            ByteWriter.WriteByte(ref data, 0x00);
        }

        return base.GetBytes(isUnicode);
    }


}