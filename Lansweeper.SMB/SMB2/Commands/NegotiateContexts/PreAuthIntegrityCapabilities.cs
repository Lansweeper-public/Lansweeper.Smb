using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2.Commands.NegotiateContexts;

/// <summary>
///     [MS-SMB2] 2.2.3.1.1 - SMB2_PREAUTH_INTEGRITY_CAPABILITIES
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       HashAlgorithmCount      |          SaltLength           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                       HashAlgorithms (variable)               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                              Salt (variable)                  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class PreAuthIntegrityCapabilities : NegotiateContext
{
    // ushort HashAlgorithmCount
    // ushort SaltLength
    public List<HashAlgorithm> HashAlgorithms { get; set; } = [];
    public byte[] Salt { get; set; } = [];

    public PreAuthIntegrityCapabilities() { }

    public PreAuthIntegrityCapabilities(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        ReadOnlySpan<byte> data = Data;
        var hashAlgorithmCount = LittleEndianReader.ReadUInt16(ref data);
        var saltLength = LittleEndianReader.ReadUInt16(ref data);
        for (var index = 0; index < hashAlgorithmCount; index++)
        {
            HashAlgorithms.Add((HashAlgorithm)LittleEndianReader.ReadUInt16(ref data));
        }
        Salt = ByteReader.ReadBytes(ref data, saltLength);
    }

    public override int DataLength => 4 + HashAlgorithms.Count * 2 + Salt.Length;

    public override NegotiateContextType ContextType => NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES;

    public override void WriteData()
    {
        Data = new byte[DataLength];
        Span<byte> data = Data;
        LittleEndianWriter.WriteUInt16(ref data, (ushort)HashAlgorithms.Count);
        LittleEndianWriter.WriteUInt16(ref data, (ushort)Salt.Length);
        for (var index = 0; index < HashAlgorithms.Count; index++)
        {
            LittleEndianWriter.WriteUInt16(ref data, (ushort)HashAlgorithms[index]);
        }
        ByteWriter.WriteBytes(ref data, Salt);
    }
}