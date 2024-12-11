using Lansweeper.Smb.SMB2.Commands;
using Lansweeper.Smb.SMB2.Commands.NegotiateContexts;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;
using System.Buffers.Binary;

namespace Lansweeper.Smb.SMB2.Commands;

/// <summary>
///     SMB2 NEGOTIATE Response
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       StructureSize           |           SecurityMode        | 
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      DialectRevision          | NegotiateContextCount/Reserved|
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   /                           ServerGuid                          /
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
///   |                          Capabilities                         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          MaxTransactSize                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          MaxReadSize                          |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          MaxWriteSize                         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                       SystemTime (FILETIME)                   /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                     ServerStartTime (FILETIME)                /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      SecurityBufferOffset     |     SecurityBufferLength      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |             NegotiateContextOffset/Reserved2                  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Buffer (variable)                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                       Padding (variable)                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                  NegotiateContextList (variable)              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   
/// 
/// </summary>
public class NegotiateResponse : Smb2Command
{
    public const int FixedSize = 64; // SecurityBuffer always starts at same offset
    public const int DeclaredSize = 65;

    public ushort StructureSize { get; }
    public SecurityMode SecurityMode { get; set; }
    public Smb2Dialect DialectRevision { get; set; }
    private ushort NegotiateContextCount { get; set; }
    public Guid ServerGuid { get; set; }
    public Capabilities Capabilities { get; set; }
    public uint MaxTransactSize { get; set; }
    public uint MaxReadSize { get; set; }
    public uint MaxWriteSize { get; set; }
    public DateTime SystemTime { get; set; }
    public DateTime ServerStartTime { get; set; }
    private ushort SecurityBufferOffset { get; set; }
    private ushort SecurityBufferLength { get; set; }
    private uint NegotiateContextOffset { get; set; }
    public byte[] SecurityBuffer { get; set; } = [];
    public List<NegotiateContext> NegotiateContextList { get; set; } = [];


    public NegotiateResponse() : base(Smb2CommandName.Negotiate)
    {
        Header.IsResponse = true;
        StructureSize = DeclaredSize;
    }

    public NegotiateResponse(ReadOnlySpan<byte> buffer) 
        : base(buffer, (Smb2Dialect)BinaryPrimitives.ReadUInt16LittleEndian(buffer[4..]))
    {
        // create a copy of the buffer to avoid modifying the original buffer
        ReadOnlySpan<byte> body = buffer[Smb2Header.Length..];

        StructureSize = LittleEndianReader.ReadUInt16(ref body);
        SecurityMode = (SecurityMode)LittleEndianReader.ReadUInt16(ref body);
        DialectRevision = (Smb2Dialect)LittleEndianReader.ReadUInt16(ref body);
        NegotiateContextCount = LittleEndianReader.ReadUInt16(ref body);
        ServerGuid = LittleEndianReader.ReadGuid(ref body);
        Capabilities = (Capabilities)LittleEndianReader.ReadUInt32(ref body);
        MaxTransactSize = LittleEndianReader.ReadUInt32(ref body);
        MaxReadSize = LittleEndianReader.ReadUInt32(ref body);
        MaxWriteSize = LittleEndianReader.ReadUInt32(ref body);
        SystemTime = LittleEndianReader.ReadFileTime(ref body);
        ServerStartTime = LittleEndianReader.ReadFileTime(ref body);
        SecurityBufferOffset = LittleEndianReader.ReadUInt16(ref body);
        SecurityBufferLength = LittleEndianReader.ReadUInt16(ref body);
        NegotiateContextOffset = LittleEndianReader.ReadUInt32(ref body);

        // go back to original buffer
        SecurityBuffer = buffer.Slice(SecurityBufferOffset, SecurityBufferLength).ToArray();
        if (DialectRevision == Smb2Dialect.SMB311)
        {
            NegotiateContextList = NegotiateContext.ReadNegotiateContextList(buffer[(int)NegotiateContextOffset..], NegotiateContextCount);
        }
    }

    public override int CommandLength
    {
        get
        {
            if (NegotiateContextList.Count == 0) return FixedSize + SecurityBuffer.Length;

            var paddedSecurityBufferLength = (int)Math.Ceiling((double)SecurityBuffer.Length / 8) * 8;
            return FixedSize + paddedSecurityBufferLength +
                   NegotiateContext.GetNegotiateContextListLength(NegotiateContextList);
        }
    }

    public override void WriteCommandBytes(Span<byte> buffer)
    {
        // make sure private properties are up to date
        SecurityBufferOffset = 0;
        SecurityBufferLength = (ushort)SecurityBuffer.Length;
        var paddedSecurityBufferLength = (int)Math.Ceiling((double)SecurityBufferLength / 8) * 8;
        if (SecurityBuffer.Length > 0)
        {
            SecurityBufferOffset = Smb2Header.Length + FixedSize;
        }
        NegotiateContextOffset = 0;
        NegotiateContextCount = (ushort)NegotiateContextList.Count;
        if (NegotiateContextList.Count > 0)
        {
            // NegotiateContextList must be 8-byte aligned
            NegotiateContextOffset = (uint)(Smb2Header.Length + FixedSize + paddedSecurityBufferLength);
        }

        // write to buffer
        LittleEndianWriter.WriteUInt16(ref buffer, StructureSize);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)SecurityMode);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)DialectRevision);
        LittleEndianWriter.WriteUInt16(ref buffer, NegotiateContextCount);
        LittleEndianWriter.WriteGuid(ref buffer, ServerGuid);
        LittleEndianWriter.WriteUInt32(ref buffer, (uint)Capabilities);
        LittleEndianWriter.WriteUInt32(ref buffer, MaxTransactSize);
        LittleEndianWriter.WriteUInt32(ref buffer, MaxReadSize);
        LittleEndianWriter.WriteUInt32(ref buffer, MaxWriteSize);
        LittleEndianWriter.WriteFileTime(ref buffer, SystemTime);
        LittleEndianWriter.WriteFileTime(ref buffer, ServerStartTime);
        LittleEndianWriter.WriteUInt16(ref buffer, SecurityBufferOffset);
        LittleEndianWriter.WriteUInt16(ref buffer, SecurityBufferLength);
        LittleEndianWriter.WriteUInt32(ref buffer, NegotiateContextOffset);
        ByteWriter.WriteBytes(ref buffer, SecurityBuffer);

        if (DialectRevision == Smb2Dialect.SMB311)
        {
            int paddingLength = paddedSecurityBufferLength - SecurityBufferLength;
            buffer[..paddingLength].Clear(); // write padding
            NegotiateContext.WriteNegotiateContextList(buffer[paddingLength..], NegotiateContextList);
        }

    }
}