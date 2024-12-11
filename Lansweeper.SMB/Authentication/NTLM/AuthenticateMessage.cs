using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.NTLM;

/// <summary>
///     [MS-NLMP] AUTHENTICATE_MESSAGE (Type 3 Message)
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                           Signature                           /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          MessageType                          | // must have value 0x00000003
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |     LmChallengeResponseLen    |   LmChallengeResponseMaxLen   | // points to location in buffer where the LmChallengeResponse is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                LmChallengeResponseBufferOffset                |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |    NtChallengeResponseLen     |   NtChallengeResponseMaxLen   | // points to location in buffer where the ntChallengeResponse is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                NtChallengeResponseBufferOffset                |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      DomainNameLen            |         DomainNameMaxLen      | // points to location in buffer where the domain name is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                     DomainNameBufferOffset                    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       UserNameLen             |          UserNameMaxLen       | // points to location in buffer where the user name is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                     UserNameBufferOffset                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      WorkstationLen           |        WorkstationMaxLen      | // points to location in buffer where the workstation is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    WorkstationBufferOffset                    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  EncryptedRandomSessionKeyLen |EncryptedRandomSessionKeyMaxLen| // points to location in buffer where the workstation is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |           EncryptedRandomSessionKeyBufferOffset               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                         NegotiateFlags                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                      Version (optional)                       /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   /                        MIC (optional)                         /
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Payload (variable)                     |  // contains LmChallengeResponse, ntChallengeResponse, DomainName, ...
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
/// 
/// </summary>
public class AuthenticateMessage
{
    public const string ValidSignature = "NTLMSSP\0";
    public static readonly ImmutableArray<byte> ValidSignatureInBytes = "NTLMSSP\0"u8.ToImmutableArray();
    public const int MicFieldLength = 16;

    public string Signature { get; set; } // 8 bytes
    public MessageTypeName MessageType { get; set; }
    public byte[] LmChallengeResponse { get; set; } // 1 byte for anonymous authentication, 24 bytes for NTLM v1, NTLM v1 Extended Session Security and NTLM v2.
    public byte[] NtChallengeResponse { get; set; } // 0 bytes for anonymous authentication, 24 bytes for NTLM v1 and NTLM v1 Extended Session Security, >= 48 bytes for NTLM v2.
    public string DomainName { get; set; }
    public string UserName { get; set; }
    public string WorkStation { get; set; }
    public byte[] EncryptedRandomSessionKey { get; set; }
    public NegotiateFlags NegotiateFlags { get; set; }
    public NtlmVersion Version { get; set; }
    public byte[]? MIC { get; set; } // 16-byte MIC field is omitted for Windows NT / 2000 / XP / Server 2003



    public AuthenticateMessage()
    {
        Signature = ValidSignature;
        MessageType = MessageTypeName.Authenticate;
        DomainName = string.Empty;
        UserName = string.Empty;
        WorkStation = string.Empty;
        EncryptedRandomSessionKey = [];
        LmChallengeResponse = [];
        NtChallengeResponse = [];
        Version = NtlmVersion.Unset;
    }

    public AuthenticateMessage(ReadOnlySpan<byte> buffer)
    {
        Signature = ByteReader.ReadAnsiString(buffer, 8);
        MessageType = (MessageTypeName)BinaryPrimitives.ReadUInt32LittleEndian(buffer[8..]);
        LmChallengeResponse = AuthenticationMessageUtils.ReadBufferPointer(buffer, 12).ToArray();
        NtChallengeResponse = AuthenticationMessageUtils.ReadBufferPointer(buffer, 20).ToArray();
        NegotiateFlags = (NegotiateFlags)BinaryPrimitives.ReadUInt32LittleEndian(buffer[60..]);
        EncryptedRandomSessionKey = AuthenticationMessageUtils.ReadBufferPointer(buffer, 52).ToArray();

        if ((NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
        {
            DomainName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 28);
            UserName = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 36);
            WorkStation = AuthenticationMessageUtils.ReadUnicodeStringBufferPointer(buffer, 44);
        }
        else
        {
            DomainName = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 28);
            UserName = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 36);
            WorkStation = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 44);
        }

        var micFieldOffset = 64;
        if ((NegotiateFlags & NegotiateFlags.Version) > 0)
        {
            Version = new NtlmVersion(buffer[64..]);
            micFieldOffset += NtlmVersion.Length;
        }
        else
        {
            Version = NtlmVersion.Unset;
        }

        if (HasMicField())
        {
            MIC = ByteReader.ReadBytes(buffer[micFieldOffset..], MicFieldLength);
        }
    }

    public bool HasMicField()
    {
        if (!AuthenticationMessageUtils.IsNtlmV2NTResponse(NtChallengeResponse)) return false;

        NtlmV2ClientChallenge challenge;
        try
        {
            challenge = new NtlmV2ClientChallenge(NtChallengeResponse.AsSpan(16));
        }
        catch
        {
            return false;
        }

        var index = challenge.AVPairs.IndexOfKey(AVPairKey.Flags);
        if (index >= 0)
        {
            var value = challenge.AVPairs[index].Value;
            if (value.Length == 4)
            {
                var flags = BinaryPrimitives.ReadUInt32LittleEndian(value);
                return (flags & 0x02) > 0;
            }
        }

        return false;
    }

    public byte[] GetBytes()
    {
        bool isUnicode = (NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0;
        bool hasKeyExchange = EncryptedRandomSessionKey.Length > 0;
        bool hasVersion = Version != NtlmVersion.Unset;

        // flags should follow properties
        if (hasKeyExchange) NegotiateFlags |= NegotiateFlags.KeyExchange;
        if (hasVersion) NegotiateFlags |= NegotiateFlags.Version;

        var fixedLength = 64;
        if (hasVersion) fixedLength += NtlmVersion.Length;
        if (MIC is not null) fixedLength += MIC.Length;

        var payloadLength = LmChallengeResponse.Length + NtChallengeResponse.Length
                            + EncryptedRandomSessionKey.Length;
        if (isUnicode)
        {
            payloadLength += DomainName.Length * 2 + UserName.Length * 2 + WorkStation.Length * 2;
        }
        else
        {
            payloadLength += DomainName.Length + UserName.Length + WorkStation.Length;
        }

        // create buffer
        var buffer = new byte[fixedLength + payloadLength];

        // write fixed part
        Span<byte> bufferSpan = buffer;
        ByteWriter.WriteBytes(bufferSpan, ValidSignatureInBytes.AsSpan());
        BinaryPrimitives.WriteUInt32LittleEndian(bufferSpan[8..12], (uint)MessageType);
        BinaryPrimitives.WriteUInt32LittleEndian(bufferSpan[60..64], (uint)NegotiateFlags);
        var offset = 64;

        // optional fields
        if (hasVersion)
        {
            Version.WriteBytes(bufferSpan[64..]);
            offset += NtlmVersion.Length;
        }

        if (MIC is not null)
        {
            ByteWriter.WriteBytes(bufferSpan[offset..], MIC);
            offset += MIC.Length;
        }

        // write payload an it's references
        // the order should not matter according to the specification.
        // However, the order here is based on samples we found
        if (isUnicode)
        {
            AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[28..], (ushort)(DomainName.Length * 2), (uint)offset);
            ByteWriter.WriteUTF16String(bufferSpan[offset..], DomainName);
            offset += DomainName.Length * 2;

            AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[36..], (ushort)(UserName.Length * 2), (uint)offset);
            ByteWriter.WriteUTF16String(bufferSpan[offset..], UserName);
            offset += UserName.Length * 2;

            AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[44..], (ushort)(WorkStation.Length * 2), (uint)offset);
            ByteWriter.WriteUTF16String(bufferSpan[offset..], WorkStation);
            offset += WorkStation.Length * 2;
        }
        else
        {
            AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[28..], (ushort)DomainName.Length, (uint)offset);
            ByteWriter.WriteAnsiString(bufferSpan[offset..], DomainName);
            offset += DomainName.Length;

            AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[36..], (ushort)UserName.Length, (uint)offset);
            ByteWriter.WriteAnsiString(bufferSpan[offset..], UserName);
            offset += UserName.Length;

            AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[44..], (ushort)WorkStation.Length, (uint)offset);
            ByteWriter.WriteAnsiString(bufferSpan[offset..], WorkStation);
            offset += WorkStation.Length;
        }

        AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[12..], (ushort)LmChallengeResponse.Length, (uint)offset);
        ByteWriter.WriteBytes(bufferSpan[offset..], LmChallengeResponse);
        offset += LmChallengeResponse.Length;

        AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[20..], (ushort)NtChallengeResponse.Length, (uint)offset);
        ByteWriter.WriteBytes(bufferSpan[offset..], NtChallengeResponse);
        offset += NtChallengeResponse.Length;

        AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[52..], (ushort)EncryptedRandomSessionKey.Length, (uint)offset);
        ByteWriter.WriteBytes(bufferSpan[offset..], EncryptedRandomSessionKey);

        return buffer;
    }

    public void CalculateMIC(byte[] sessionKey, byte[] negotiateMessage, byte[] challengeMessage)
    {
        MIC = new byte[MicFieldLength];
        var authenticateMessageBytes = GetBytes();
        byte[] temp = [.. negotiateMessage, .. challengeMessage, .. authenticateMessageBytes];
        MIC = HMACMD5.HashData(sessionKey, temp);
    }

    public static int GetMicFieldOffset(ReadOnlySpan<byte> authenticateMessageBytes)
    {
        var negotiateFlags = (NegotiateFlags)BinaryPrimitives.ReadUInt32LittleEndian(authenticateMessageBytes[60..]);
        var offset = 64;
        if ((negotiateFlags & NegotiateFlags.Version) > 0)
        {
            offset += NtlmVersion.Length;
        }

        return offset;
    }
}