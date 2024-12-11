using Lansweeper.Smb.Utilities;
using System.Buffers.Binary;

namespace Lansweeper.Smb.Authentication.NTLM;

/// <summary>
///     [MS-NLMP] NEGOTIATE_MESSAGE (Type 1 Message)
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                           Signature                           /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          MessageType                          | // must have value 0x00000001
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                         NegotiateFlags                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      DomainNameLen            |         DomainNameMaxLen      | // points to location in buffer where the domain name is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                     DomainNameBufferOffset                    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      WorkstationLen           |        WorkstationMaxLen      | // points to location in buffer where the workstation is stored
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    WorkstationBufferOffset                    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                       Version (optional)                      /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Payload (variable)                     |  // contains DomainName and Workstation
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
/// 
/// </summary>
public class NegotiateMessage
{
    public string Signature { get; set; } // 8 bytes
    public MessageTypeName MessageType { get; set; }
    public NegotiateFlags NegotiateFlags { get; set; }
    public string DomainName { get; set; }
    public string Workstation { get; set; }
    public NtlmVersion Version { get; set; }

    public NegotiateMessage()
    {
        Signature = AuthenticateMessage.ValidSignature;
        MessageType = MessageTypeName.Negotiate;
        DomainName = string.Empty;
        Workstation = string.Empty;
        Version = NtlmVersion.Unset;
    }

    public NegotiateMessage(ReadOnlySpan<byte> buffer)
    {
        Signature = ByteReader.ReadAnsiString(buffer, 8);
        MessageType = (MessageTypeName)BinaryPrimitives.ReadUInt32LittleEndian(buffer[8..]);
        NegotiateFlags = (NegotiateFlags)BinaryPrimitives.ReadUInt32LittleEndian(buffer[12..]);
        DomainName = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 16);
        Workstation = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 24);

        Version = (NegotiateFlags & NegotiateFlags.Version) > 0
            ? new NtlmVersion(buffer[32..])
            : NtlmVersion.Unset;
    }

    /// <remarks>This implementation only supports unicode</remarks>
    /// <exception cref="NotImplementedException"/>
    public byte[] GetBytes()
    {
        bool hasDomainName = !string.IsNullOrEmpty(DomainName);
        bool hasWorkstationName = !string.IsNullOrEmpty(Workstation);
        bool hasVersion = Version != NtlmVersion.Unset;

        // flags should follow properties
        if (hasDomainName) NegotiateFlags |= NegotiateFlags.DomainNameSupplied;
        if (hasWorkstationName) NegotiateFlags |= NegotiateFlags.WorkstationNameSupplied;
        if (hasVersion) NegotiateFlags |= NegotiateFlags.Version;

        var fixedLength = 32;
        if (hasVersion) fixedLength += NtlmVersion.Length;


        var payloadLength = DomainName.Length + Workstation.Length; // MUST be encoded using the OEM character set
        byte[] buffer = new byte[fixedLength + payloadLength];
        Span<byte> bufferSpan = buffer;

        ByteWriter.WriteBytes(bufferSpan, AuthenticateMessage.ValidSignatureInBytes.AsSpan());
        BinaryPrimitives.WriteUInt32LittleEndian(bufferSpan[8..12], (uint)MessageType);
        BinaryPrimitives.WriteUInt32LittleEndian(bufferSpan[12..16], (uint)NegotiateFlags);

        if (hasVersion)
        {
            Version.WriteBytes(bufferSpan[32..]);
        }

        // MUST be encoded using the OEM character set, even if the NegotiateFlags.UnicodeEncoding flag is set
        var offset = fixedLength;
        AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[16..], (ushort)(DomainName.Length), (uint)offset);
        ByteWriter.WriteAnsiString(bufferSpan[offset..], DomainName);
        offset += DomainName.Length;

        AuthenticationMessageUtils.WriteBufferPointer(bufferSpan[24..], (ushort)(Workstation.Length), (uint)offset);
        ByteWriter.WriteAnsiString(bufferSpan[offset..], Workstation);

        return buffer;
    }
}