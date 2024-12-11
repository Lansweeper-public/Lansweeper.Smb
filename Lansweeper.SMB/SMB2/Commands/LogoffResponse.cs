using Lansweeper.Smb.SMB2.Commands;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2.Commands;

/// <summary>
///     SMB2 LOGOFF Response
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      StructureSize            |            Reserved           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class LogoffResponse : Smb2Command
{
    public const int DeclaredSize = 4;

    private ushort StructureSize { get; }
    public ushort Reserved { get; set; }

    public LogoffResponse() : base(Smb2CommandName.Logoff)
    {
        Header.IsResponse = true;
        StructureSize = DeclaredSize;
    }

    public LogoffResponse(ReadOnlySpan<byte> buffer, Smb2Dialect dialect) : base(buffer, dialect)
    {
        buffer = buffer[Smb2Header.Length..];
        StructureSize = LittleEndianReader.ReadUInt16(ref buffer);
        Reserved = LittleEndianReader.ReadUInt16(ref buffer);
    }

    public override int CommandLength => DeclaredSize;

    public override void WriteCommandBytes(Span<byte> buffer)
    {
        LittleEndianWriter.WriteUInt16(ref buffer, StructureSize);
        LittleEndianWriter.WriteUInt16(ref buffer, Reserved);
    }
}