using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;
using System.Buffers.Binary;

namespace Lansweeper.Smb.SMB1.Commands;

public abstract class SmbAndXCommand : Smb1Command
{
    public CommandName AndXCommand { get; set; }
    /// <remarks> should always be 0x00 </remarks>
    public byte AndXReserved { get; }
    public ushort AndXOffset { get; set; }

    protected SmbAndXCommand() { }

    protected SmbAndXCommand(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        ReadOnlySpan<byte> parameters = SMBParameters;
        AndXCommand = (CommandName)ByteReader.ReadByte(ref parameters);
        AndXReserved = ByteReader.ReadByte(ref parameters);
        AndXOffset = BinaryPrimitives.ReadUInt16LittleEndian(parameters);
    }

    public override byte[] GetBytes(bool isUnicode)
    {
        Span<byte> parameters = SMBParameters;
        ByteWriter.WriteByte(ref parameters, (byte)AndXCommand);
        ByteWriter.WriteByte(ref parameters, AndXReserved);
        LittleEndianWriter.WriteUInt16(ref parameters, AndXOffset);
        return base.GetBytes(isUnicode);
    }

    public static void WriteAndXOffset(Span<byte> command, ushort AndXOffset)
    {
        // 3 preceding bytes: WordCount, AndXCommand and AndXReserved
        LittleEndianWriter.WriteUInt16(command[3..], AndXOffset);

    }
}