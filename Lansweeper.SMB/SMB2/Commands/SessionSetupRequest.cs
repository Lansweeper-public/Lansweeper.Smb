using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2.Commands;

/// <summary>
///     SMB2 SESSION_SETUP Request
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         StructureSize         |    Flags      |  SecurityMode |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          Capabilities                         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          Channel                              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      SecurityBufferOffset     |     SecurityBufferLength      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                       PreviousSessionId                       /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Buffer (variable)                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   
/// 
/// </summary>
public class SessionSetupRequest : Smb2Command
{
    public const int FixedSize = 24; // SecurityBuffer always starts at same offset
    public const int DeclaredSize = 25;

    private ushort StructureSize { get; }
    public SessionSetupFlags Flags { get; set; }
    public SecurityMode SecurityMode { get; set; }
    /// <remarks> Values other than SMB2_GLOBAL_CAP_DFS should be treated as reserved. </remarks>
    public Capabilities Capabilities { get; set; }
    public uint Channel { get; set; }
    public ulong PreviousSessionId { get; set; }
    private ushort SecurityBufferLength { get; set; }
    private ushort SecurityBufferOffset { get; set; }
    public byte[] SecurityBuffer { get; set; } = [];


    public SessionSetupRequest() : base(Smb2CommandName.SessionSetup)
    {
        StructureSize = DeclaredSize;
    }

    public SessionSetupRequest(ReadOnlySpan<byte> buffer, Smb2Dialect dialect) : base(buffer, dialect)
    {
        ReadOnlySpan<byte> body = buffer[Smb2Header.Length..];
        StructureSize = LittleEndianReader.ReadUInt16(ref body);
        Flags = (SessionSetupFlags)ByteReader.ReadByte(ref body);
        SecurityMode = (SecurityMode)ByteReader.ReadByte(ref body);
        Capabilities = (Capabilities)LittleEndianReader.ReadUInt32(ref body);
        Channel = LittleEndianReader.ReadUInt32(ref body);
        SecurityBufferOffset = LittleEndianReader.ReadUInt16(ref body);
        SecurityBufferLength = LittleEndianReader.ReadUInt16(ref body);
        PreviousSessionId = LittleEndianReader.ReadUInt64(ref body);
        if (SecurityBufferLength > 0)
        {
            SecurityBuffer = buffer.Slice(SecurityBufferOffset, SecurityBufferLength).ToArray();
        }
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
        ByteWriter.WriteByte(ref buffer, (byte)Flags);
        ByteWriter.WriteByte(ref buffer, (byte)SecurityMode);
        LittleEndianWriter.WriteUInt32(ref buffer, (uint)Capabilities);
        LittleEndianWriter.WriteUInt32(ref buffer, Channel);
        LittleEndianWriter.WriteUInt16(ref buffer, SecurityBufferOffset);
        LittleEndianWriter.WriteUInt16(ref buffer, SecurityBufferLength);
        LittleEndianWriter.WriteUInt64(ref buffer, PreviousSessionId);
        ByteWriter.WriteBytes(buffer, SecurityBuffer);
    }

}