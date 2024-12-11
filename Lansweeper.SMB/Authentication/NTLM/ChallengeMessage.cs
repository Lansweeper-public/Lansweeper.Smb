using Lansweeper.Smb.Utilities;
using System.Buffers.Binary;

namespace Lansweeper.Smb.Authentication.NTLM;

/// <summary>
///     [MS-NLMP] CHALLENGE_MESSAGE (Type 2 Message)
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                           Signature                           /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          MessageType                          | // must have value 0x00000002
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          TargetNameLen        |       TargetNameMaxLen        | // points to location in buffer where the target name is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    TargetNameBufferOffset                     |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                         NegotiateFlags                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                          ServerChallenge                      /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                          Reserved                             /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |           TargetInfoLen       |       TargetInfoMaxLen        | // points to location in buffer where the target info is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    TargetInfoBufferOffset                     |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                      Version (optional)                       /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Payload (variable)                     |  // contains LmChallengeResponse, ntChallengeResponse, DomainName, ...
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
/// </summary>
public class ChallengeMessage
{
    public string Signature { get; set; } // 8 bytes
    public MessageTypeName MessageType { get; set; }
    public string TargetName { get; set; }
    public NegotiateFlags NegotiateFlags { get; set; }
    public byte[] ServerChallenge { get; set; } // 8 bytes
    // Reserved - 8 bytes
    public KeyValuePairList<AVPairKey, byte[]> TargetInfo { get; set; } = [];
    public NtlmVersion Version { get; set; }


    public ChallengeMessage()
    {
        Signature = AuthenticateMessage.ValidSignature;
        MessageType = MessageTypeName.Challenge;
        TargetName = string.Empty;
        ServerChallenge = [];
        Version = NtlmVersion.Unset;
    }

    public ChallengeMessage(ReadOnlySpan<byte> buffer)
    {
        Signature = ByteReader.ReadAnsiString(buffer, 8);
        MessageType = (MessageTypeName)BinaryPrimitives.ReadUInt32LittleEndian(buffer[8..]);
        NegotiateFlags = (NegotiateFlags)BinaryPrimitives.ReadUInt32LittleEndian(buffer[20..]);
        ServerChallenge = buffer[24..32].ToArray();

        if ((NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
        {
            TargetName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 12);
        }
        else
        {
            TargetName = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 12);
        }
        // Reserved (8 bytes)
        var targetInfoBytes = AuthenticationMessageUtils.ReadBufferPointer(buffer, 40);
        if (targetInfoBytes.Length > 0)
        {
            TargetInfo = AVPairUtils.ReadAVPairSequence(targetInfoBytes);
        }

        Version = (NegotiateFlags & NegotiateFlags.Version) > 0
            ? new NtlmVersion(buffer[48..])
            : NtlmVersion.Unset;
    }

    public byte[] GetBytes()
    {
        bool isUnicode = (NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0;
        bool hasTargetName = !string.IsNullOrEmpty(TargetName);
        bool hasTargetInfo = TargetInfo.Count > 0;
        bool hasVersion = Version != NtlmVersion.Unset;

        // flags should follow properties
        if (hasTargetName) NegotiateFlags |= NegotiateFlags.TargetNameSupplied;
        if (hasTargetInfo) NegotiateFlags |= NegotiateFlags.TargetInfo;
        if (hasVersion) NegotiateFlags |= NegotiateFlags.Version;

        var fixedLength = 48;
        if (hasVersion) fixedLength += NtlmVersion.Length;

        var payloadLength = isUnicode ? TargetName.Length * 2 : TargetName.Length;

        byte[]? targetInfoBytes = null;
        if (hasTargetInfo)
        {
            targetInfoBytes = AVPairUtils.GetAVPairSequenceBytes(TargetInfo);
            payloadLength += targetInfoBytes.Length;
        }

        // create buffer
        var buffer = new byte[fixedLength + payloadLength];

        // write fixed part
        Span<byte> bufferSpan = buffer;
        ByteWriter.WriteBytes(bufferSpan, AuthenticateMessage.ValidSignatureInBytes.AsSpan());
        BinaryPrimitives.WriteUInt32LittleEndian(bufferSpan[8..12], (uint)MessageType);
        BinaryPrimitives.WriteUInt32LittleEndian(bufferSpan[20..24], (uint)NegotiateFlags);
        ByteWriter.WriteBytes(bufferSpan[24..], ServerChallenge);

        if (hasVersion)
        {
            Version.WriteBytes(bufferSpan[48..]);
        }

        // write payload
        var offset = fixedLength; // offset to start writing the payload

        if (isUnicode)
        {
            AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[12..], (ushort)(TargetName.Length * 2), (uint)offset);
            ByteWriter.WriteUTF16String(bufferSpan[offset..], TargetName);
            offset += TargetName.Length * 2;
        }
        else
        {
            AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[12..], (ushort)TargetName.Length, (uint)offset);
            ByteWriter.WriteAnsiString(bufferSpan[offset..], TargetName);
            offset += TargetName.Length;
        }


        //If a TargetInfo AV_PAIR Value is textual, it MUST be encoded in Unicode irrespective
        //of what character set was negotiated
        AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[40..], (ushort)targetInfoBytes!.Length, (uint)offset);
        ByteWriter.WriteBytes(bufferSpan[offset..], targetInfoBytes);

        return buffer;
    }

    public string? ReadTargetInfoValue(AVPairKey key)
    {
        byte[]? valueInBytes = TargetInfo.ValueOf(key);
        if (valueInBytes == null) return null;

        return (NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0
            ? ByteReader.ReadUTF16String(valueInBytes)
            : ByteReader.ReadAnsiString(valueInBytes);
    }
}