using Lansweeper.Smb.SMB2.Commands;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2.Commands;

/// <summary>
///     SMB2 SESSION_SETUP Response
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |        StructureSize          |        SessionFlags           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      SecurityBufferOffset     |     SecurityBufferLength      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Buffer (variable)                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   
/// </summary>
public class SessionSetupResponse : Smb2Command
{
    public const int FixedSize = 8; // SecurityBuffer always starts at same offset
    public const int DeclaredSize = 9;

    private ushort StructureSize { get; }
    public SessionFlags SessionFlags { get; set; }
    private ushort SecurityBufferLength { get; set; }
    private ushort SecurityBufferOffset { get; set; }
    public byte[] SecurityBuffer { get; set; } = [];


    public SessionSetupResponse() : base(Smb2CommandName.SessionSetup)
    {
        Header.IsResponse = true;
        StructureSize = DeclaredSize;
    }

    public SessionSetupResponse(ReadOnlySpan<byte> buffer, Smb2Dialect dialect) : base(buffer, dialect)
    {
        ReadOnlySpan<byte> body = buffer[Smb2Header.Length..];
        StructureSize = LittleEndianReader.ReadUInt16(ref body);
        SessionFlags = (SessionFlags)LittleEndianReader.ReadUInt16(ref body);
        SecurityBufferOffset = LittleEndianReader.ReadUInt16(ref body);
        SecurityBufferLength = LittleEndianReader.ReadUInt16(ref body);
        SecurityBuffer = buffer.Slice(SecurityBufferOffset, SecurityBufferLength).ToArray();
    }

    public override int CommandLength => FixedSize + SecurityBuffer.Length;

    public override void WriteCommandBytes(Span<byte> buffer)
    {
        // make sure private properties are up to date
        SecurityBufferOffset = 0;
        SecurityBufferLength = (ushort)SecurityBuffer.Length;
        if (SecurityBuffer.Length > 0)
        {
            SecurityBufferOffset = Smb2Header.Length + FixedSize;
        }

        // write to buffer
        LittleEndianWriter.WriteUInt16(ref buffer, StructureSize);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)SessionFlags);
        LittleEndianWriter.WriteUInt16(ref buffer, SecurityBufferOffset);
        LittleEndianWriter.WriteUInt16(ref buffer, SecurityBufferLength);
        ByteWriter.WriteBytes(ref buffer, SecurityBuffer);
    }
}