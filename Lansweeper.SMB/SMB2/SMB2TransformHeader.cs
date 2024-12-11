using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2;

/// <summary>
///     Used by the client or server when sending encrypted messages. only valid for the SMB 3.x dialect family.
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        ProtocolId                             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   /                        Signature                              /
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   /                          Nonce                                /
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                   OriginalMessageSize                         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |            Reserved           |   Flags/EncryptionAlgorithm   |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                        SessionId                              /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   
/// </summary>
public class Smb2TransformHeader
{
    public const int Length = 52;
    public const int SignatureLength = 16;
    public const int NonceLength = 16;
    private const int NonceStartOffset = 20;
    public static readonly byte[] ProtocolSignature = [0xFD, 0x53, 0x4D, 0x42];

    private byte[] ProtocolId { get; } // 4 bytes, 0xFD followed by "SMB"
    public byte[] Signature { get; set; } // 16 bytes
    public byte[] Nonce { get; set; } // 16 bytes
    public uint OriginalMessageSize { get; set; }
    public ushort Reserved { get; set; }
    public Smb2TransformHeaderFlags Flags { get; set; } // EncryptionAlgorithm in SMB 3.0 / 3.0.2 where the only possible value is SMB2_ENCRYPTION_AES128_CCM = 0x0001 
    public ulong SessionId { get; set; }

    public Smb2TransformHeader()
    {
        ProtocolId = ProtocolSignature;
        Signature = new byte[16];
        Nonce = new byte[16];
    }

    public Smb2TransformHeader(ReadOnlySpan<byte> buffer)
    {
        ProtocolId = ByteReader.ReadBytes(ref buffer, 4);
        Signature = ByteReader.ReadBytes(ref buffer, SignatureLength);
        Nonce = ByteReader.ReadBytes(ref buffer, NonceLength);
        OriginalMessageSize = LittleEndianReader.ReadUInt32(ref buffer);
        Reserved = LittleEndianReader.ReadUInt16(ref buffer);
        Flags = (Smb2TransformHeaderFlags)LittleEndianReader.ReadUInt16(ref buffer);
        SessionId = LittleEndianReader.ReadUInt64(ref buffer);
    }

    public void WriteBytes(Span<byte> buffer)
    { 
        ByteWriter.WriteBytes(ref buffer, ProtocolId);
        ByteWriter.WriteBytes(ref buffer, Signature);
        WriteAssociatedData(buffer);
    }

    private void WriteAssociatedData(Span<byte> buffer)
    {
        ByteWriter.WriteBytes(ref buffer, Nonce);
        LittleEndianWriter.WriteUInt32(ref buffer, OriginalMessageSize);
        LittleEndianWriter.WriteUInt16(ref buffer, Reserved);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)Flags);
        LittleEndianWriter.WriteUInt64(ref buffer, SessionId);
    }

    public byte[] GetAssociatedData()
    {
        var buffer = new byte[Length - NonceStartOffset];
        WriteAssociatedData(buffer);
        return buffer;
    }

    public static bool IsTransformHeader(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 4) return false;

        return buffer[0] == ProtocolSignature[0] && // fast check
               buffer[1] == ProtocolSignature[1] &&
               buffer[2] == ProtocolSignature[2] &&
               buffer[3] == ProtocolSignature[3];
    }
}