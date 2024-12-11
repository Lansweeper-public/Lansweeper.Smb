using Lansweeper.Smb.Enums;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2.Commands;

/// <summary>
///     SMB2 ERROR Response
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      StructureSize            | ErrContextCnt |   Reserved    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                         ByteCount                             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                     ErrorData (variable)                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                              ...                              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class ErrorResponse : Smb2Command
{
    public const int FixedSize = 8;
    public const int DeclaredSize = 9;
    private uint ByteCount { get; set; }
    public byte ErrorContextCount { get; set; }
    public byte[] ErrorData { get; set; } = [];
    public byte Reserved { get; set; }

    private readonly ushort StructureSize;

    public ErrorResponse(Smb2CommandName commandName) : base(commandName)
    {
        Header.IsResponse = true;
        StructureSize = DeclaredSize;
    }

    public ErrorResponse(Smb2CommandName commandName, NTStatus status) : base(commandName)
    {
        Header.IsResponse = true;
        StructureSize = DeclaredSize;
        Header.Status = status;
    }

    public ErrorResponse(Smb2CommandName commandName, NTStatus status, byte[] errorData) : base(commandName)
    {
        Header.IsResponse = true;
        StructureSize = DeclaredSize;
        Header.Status = status;
        ErrorData = errorData;
    }

    public ErrorResponse(ReadOnlySpan<byte> buffer, Smb2Dialect dialect) : base(buffer, dialect)
    {
        buffer = buffer[Smb2Header.Length..];
        StructureSize = LittleEndianReader.ReadUInt16(ref buffer);
        ErrorContextCount = ByteReader.ReadByte(ref buffer);
        Reserved = ByteReader.ReadByte(ref buffer);
        ByteCount = LittleEndianReader.ReadUInt32(ref buffer);
        ErrorData = ByteReader.ReadBytes(ref buffer, (int)ByteCount);
    }

    public override int CommandLength => FixedSize + ErrorData.Length;

    public override void WriteCommandBytes(Span<byte> buffer)
    {
        ByteCount = (uint)ErrorData.Length;
        LittleEndianWriter.WriteUInt16(ref buffer, StructureSize);
        ByteWriter.WriteByte(ref buffer, ErrorContextCount);
        ByteWriter.WriteByte(ref buffer, Reserved);
        LittleEndianWriter.WriteUInt32(ref buffer, ByteCount);
        ByteWriter.WriteBytes(ref buffer, ErrorData);
    }
}