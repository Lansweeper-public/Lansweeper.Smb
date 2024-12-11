using System.Buffers.Binary;
using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.2.1.1. HEADER
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          QDCOUNT              |           ANCOUNT             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          NSCOUNT              |           ARCOUNT             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class NameServicePacketHeader
{
    public const int Length = 12;
    public ushort ANCount { get; set; }
    public ushort ARCount { get; set; }
    public OperationFlags Flags { get; set; }
    public ushort NSCount { get; set; }
    public NameServiceOperation OpCode { get; set; }
    public ushort QDCount { get; set; }
    public byte ResultCode { get; set; }
    public ushort TransactionID { get; set; }

    public NameServicePacketHeader() { }

    public NameServicePacketHeader(ReadOnlySpan<byte> buffer)
    {
        TransactionID = BinaryPrimitives.ReadUInt16BigEndian(buffer);
        var temp = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2));
        ResultCode = (byte)(temp & 0xF);
        Flags = (OperationFlags)((temp >> 4) & 0x7F);
        OpCode = (NameServiceOperation)((temp >> 11) & 0x1F);
        QDCount = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(4));
        ANCount = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(6));
        NSCount = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(8));
        ARCount = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(10));
    }

    public void WriteBytes(Stream stream)
    {
        BigEndianWriter.WriteUInt16(stream, TransactionID);
        var temp = (ushort)(ResultCode & 0xF);
        temp |= (ushort)((byte)Flags << 4);
        temp |= (ushort)((byte)OpCode << 11);
        BigEndianWriter.WriteUInt16(stream, temp);
        BigEndianWriter.WriteUInt16(stream, QDCount);
        BigEndianWriter.WriteUInt16(stream, ANCount);
        BigEndianWriter.WriteUInt16(stream, NSCount);
        BigEndianWriter.WriteUInt16(stream, ARCount);
    }
}