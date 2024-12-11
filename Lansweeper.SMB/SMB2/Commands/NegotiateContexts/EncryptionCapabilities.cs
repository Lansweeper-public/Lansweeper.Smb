using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2.Commands.NegotiateContexts;

/// <summary>
///     [MS-SMB2] 2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         CipherCount           |      Ciphers (variable)      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class EncryptionCapabilities : NegotiateContext
{
    // ushort CipherCount
    public List<CipherAlgorithm> Ciphers { get; set; } = [];

    public EncryptionCapabilities() { }

    public EncryptionCapabilities(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        ReadOnlySpan<byte> data = Data;
        var cipherCount = LittleEndianReader.ReadUInt16(ref data);
        for (var index = 0; index < cipherCount; index++)
        {
            Ciphers.Add((CipherAlgorithm)LittleEndianReader.ReadUInt16(ref data));
        }
    }

    public override int DataLength => 2 + Ciphers.Count * 2;

    public override NegotiateContextType ContextType => NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES;

    public override void WriteData()
    {
        Data = new byte[DataLength];
        Span<byte> data = Data;
        LittleEndianWriter.WriteUInt16(ref data, (ushort)Ciphers.Count);
        for (var index = 0; index < Ciphers.Count; index++)
        {
            LittleEndianWriter.WriteUInt16(ref data, (ushort)Ciphers[index]);
        }
    }

}