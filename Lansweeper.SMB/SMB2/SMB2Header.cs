using Lansweeper.Smb.Enums;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;
using System.Buffers.Binary;

namespace Lansweeper.Smb.SMB2;

/// <summary>
/// SMB2 Packet Header
/// 
/// There are two variants of this header: ASYNC and SYNC
/// The header looks different in both cases
/// 
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        ProtocolId                             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      StructureSize            |             CreditCharge      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |            (ChannelSequence,Reserved)/Status                  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |            Command              | CreditRequest/CreditResponse|
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                            Flags                              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          NextCommand                          |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                          MessageId                            /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                   AsyncId (for Async version)                 |
///   /                                                               /
///   |                  or TreeId and Reserved (for Sync version)    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                          SessionId                            /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   /                          Signature                            /
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 
/// </summary>
public class Smb2Header
{
    public const int Length = 64;
    public const int SignatureOffset = 48;
    public static readonly byte[] ProtocolSignature = [0xFE, 0x53, 0x4D, 0x42];
    private static readonly byte[] EmptySignature = new byte[16];

    /// <summary>
    /// 4 bytes, 0xFE followed by "SMB"
    /// </summary>
    private byte[] ProtocolId { get; }
    /// <remarks> must be 64 </remarks>
    private ushort StructureSize { get; }
    public ushort CreditCharge { get; set; }
    /// <remarks>
    /// Always used for Responses.
    /// For Requests, it depends on the dialect. In the SMB 3.x dialect family, 
    /// this field is interpreted as the <see cref="ChannelSequence"> field followed by the <see cref="Reserved"> field in a request
    /// </remarks>
    public NTStatus Status { get; set; }
    /// <remarks> Only used in requests in the SMB 3.x dialect family. </remarks>
    public ushort ChannelSequence { get; set; }
    /// <remarks> Only used in requests in the SMB 3.x dialect family. Should alwys be set to 0x0000 </remarks>
    public ushort ChannelSequenceReserved { get; set; }
    /// <summary>
    /// On a request, this field indicates the number of credits 
    /// the client is requesting.On a response, it indicates the number of credits granted to the client.
    /// </summary>
    public ushort Credits { get; set; }
    public Smb2CommandName Command { get; set; }
    public Smb2PacketHeaderFlags Flags { get; set; }
    /// <summary>
    /// Offset to next command in bytes
    /// </summary>
    public uint NextCommand { get; set; }
    public ulong MessageID { set; get; }
    /// <remarks> only found in the Async version</remarks>
    public ulong AsyncID { get; set; }
    /// <remarks> only found in the Sync version</remarks>
    public uint Reserved { get; set; }
    /// <remarks> only found in the Sync version</remarks>
    public uint TreeID { get; set; }
    public ulong SessionID { get; set; }
    /// <summary>
    /// 16 bytes (present if SMB2_FLAGS_SIGNED is set)
    /// </summary>
    public byte[] Signature { get; set; }

    public Smb2Header(Smb2CommandName commandName)
    {
        ProtocolId = ProtocolSignature;
        StructureSize = Length;
        Command = commandName;
        Signature = EmptySignature;
    }

    public Smb2Header(ReadOnlySpan<byte> buffer, Smb2Dialect dialect)
    {
        ProtocolId = ByteReader.ReadBytes(ref buffer, 4);
        StructureSize = LittleEndianReader.ReadUInt16(ref buffer);
        CreditCharge = LittleEndianReader.ReadUInt16(ref buffer);

        // skip ChannelSequence/Reserved or Status, depends on flags
        ReadOnlySpan<byte> statusBuffer = buffer[..4];
        buffer = buffer[4..];

        Command = (Smb2CommandName)LittleEndianReader.ReadUInt16(ref buffer);
        Credits = LittleEndianReader.ReadUInt16(ref buffer);
        Flags = (Smb2PacketHeaderFlags)LittleEndianReader.ReadUInt32(ref buffer);
        NextCommand = LittleEndianReader.ReadUInt32(ref buffer);
        MessageID = LittleEndianReader.ReadUInt64(ref buffer);

        // Requests in the SMB 3.x dialect family have a different header structure
        if (!IsResponse && dialect >= Smb2Dialect.SMB300)
        {
            ChannelSequence = LittleEndianReader.ReadUInt16(ref statusBuffer);
            ChannelSequenceReserved = LittleEndianReader.ReadUInt16(ref statusBuffer);
        }
        else
        {
            Status = (NTStatus)BinaryPrimitives.ReadUInt32LittleEndian(statusBuffer);
        }

        // Check if Sync or Async --> AsyncID or Reserved and TreeID
        if ((Flags & Smb2PacketHeaderFlags.AsyncCommand) > 0)
        {
            AsyncID = LittleEndianReader.ReadUInt64(ref buffer);
        }
        else
        {
            Reserved = LittleEndianReader.ReadUInt32(ref buffer);
            TreeID = LittleEndianReader.ReadUInt32(ref buffer);
        }

        SessionID = LittleEndianReader.ReadUInt64(ref buffer);
        Signature = (Flags & Smb2PacketHeaderFlags.Signed) > 0 
            ? ByteReader.ReadBytes(ref buffer, 16) 
            : EmptySignature;
    }


    public bool IsResponse
    {
        get => (Flags & Smb2PacketHeaderFlags.ServerToRedir) > 0;
        set
        {
            if (value)
                Flags |= Smb2PacketHeaderFlags.ServerToRedir;
            else
                Flags &= ~Smb2PacketHeaderFlags.ServerToRedir;
        }
    }

    public bool IsAsync
    {
        get => (Flags & Smb2PacketHeaderFlags.AsyncCommand) > 0;
        set
        {
            if (value)
                Flags |= Smb2PacketHeaderFlags.AsyncCommand;
            else
                Flags &= ~Smb2PacketHeaderFlags.AsyncCommand;
        }
    }

    public bool IsRelatedOperations
    {
        get => (Flags & Smb2PacketHeaderFlags.RelatedOperations) > 0;
        set
        {
            if (value)
                Flags |= Smb2PacketHeaderFlags.RelatedOperations;
            else
                Flags &= ~Smb2PacketHeaderFlags.RelatedOperations;
        }
    }

    public bool IsSigned
    {
        get => (Flags & Smb2PacketHeaderFlags.Signed) > 0;
        set
        {
            if (value)
                Flags |= Smb2PacketHeaderFlags.Signed;
            else
                Flags &= ~Smb2PacketHeaderFlags.Signed;
        }
    }

    public byte Priority
    {
        get => (byte)((int)(Flags & Smb2PacketHeaderFlags.PriorityMask) >> 4);
        set
        {
            Flags &= ~Smb2PacketHeaderFlags.PriorityMask; // Clear current priority
            Flags |= (Smb2PacketHeaderFlags)((value << 4) & 0x00000070); // Set new priority
        }
    }

    public void WriteBytes(Span<byte> buffer, Smb2Dialect dialect)
    {
        ByteWriter.WriteBytes(ref buffer, ProtocolId);
        LittleEndianWriter.WriteUInt16(ref buffer, StructureSize);
        LittleEndianWriter.WriteUInt16(ref buffer, CreditCharge);

        // Requests in the SMB 3.x dialect family have a different header structure
        if (!IsResponse && dialect >= Smb2Dialect.SMB300)
        {
            LittleEndianWriter.WriteUInt16(ref buffer, ChannelSequence);
            LittleEndianWriter.WriteUInt16(ref buffer, ChannelSequenceReserved);
        }
        else
        {
            LittleEndianWriter.WriteUInt32(ref buffer, (uint)Status);
        }

        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)Command);
        LittleEndianWriter.WriteUInt16(ref buffer, Credits);
        LittleEndianWriter.WriteUInt32(ref buffer, (uint)Flags);
        LittleEndianWriter.WriteUInt32(ref buffer, NextCommand);
        LittleEndianWriter.WriteUInt64(ref buffer, MessageID);

        if (IsAsync)
        {
            LittleEndianWriter.WriteUInt64(ref buffer, AsyncID);
        }
        else
        {
            LittleEndianWriter.WriteUInt32(ref buffer, Reserved);
            LittleEndianWriter.WriteUInt32(ref buffer, TreeID);
        }

        LittleEndianWriter.WriteUInt64(ref buffer, SessionID);
        if (IsSigned)
        {
            ByteWriter.WriteBytes(ref buffer, Signature);
        }
    }

    public static bool IsValidSMB2Header(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 4) return false;

        return buffer[0] == ProtocolSignature[0] && // fast check
               buffer[1] == ProtocolSignature[1] &&
               buffer[2] == ProtocolSignature[2] &&
               buffer[3] == ProtocolSignature[3];
    }
}