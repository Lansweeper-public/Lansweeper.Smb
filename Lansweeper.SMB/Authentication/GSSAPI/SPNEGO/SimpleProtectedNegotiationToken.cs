using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;

public abstract class SimpleProtectedNegotiationToken
{
    public const byte ApplicationTag = 0x60;

    public static readonly byte[] SPNEGOIdentifier = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

    public abstract byte[] GetBytes();

    /// <param name="includeHeader">Prepend the generic GSSAPI header. Required for negTokenInit, optional for negTokenResp.</param>
    public byte[] GetBytes(bool includeHeader)
    {
        var tokenBytes = GetBytes();
        if (includeHeader)
        {
            var objectIdentifierFieldSize = DerEncodingHelper.GetLengthFieldSize(SPNEGOIdentifier.Length);
            var tokenLength = 1 + objectIdentifierFieldSize + SPNEGOIdentifier.Length + tokenBytes.Length;
            var tokenLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(tokenLength);
            var headerLength = 1 + tokenLengthFieldSize + 1 + objectIdentifierFieldSize + SPNEGOIdentifier.Length;
            var buffer = new byte[headerLength + tokenBytes.Length];
            var bufferSpan = buffer.AsSpan();
            ByteWriter.WriteByte(ref bufferSpan, ApplicationTag);
            DerEncodingHelper.WriteLength(ref bufferSpan, tokenLength);
            ByteWriter.WriteByte(ref bufferSpan, (byte)DerEncodingTag.ObjectIdentifier);
            DerEncodingHelper.WriteLength(ref bufferSpan, SPNEGOIdentifier.Length);
            ByteWriter.WriteBytes(ref bufferSpan, SPNEGOIdentifier);
            ByteWriter.WriteBytes(ref bufferSpan, tokenBytes);
            return buffer;
        }

        return tokenBytes;
    }

    /// <summary>
    ///     https://tools.ietf.org/html/rfc2743
    /// </summary>
    /// <exception cref="InvalidDataException"></exception>
    public static SimpleProtectedNegotiationToken? ReadToken(ReadOnlySpan<byte> tokenBytes, bool serverInitiatedNegotiation)
    {
        var tag = tokenBytes[0]; // read first byte to figure out type
        if (tag == ApplicationTag)
        {
            // https://msdn.microsoft.com/en-us/library/ms995330.aspx
            // when an InitToken is sent, it is prepended by an Application Constructed Object specifier (0x60),
            // and the OID for SPNEGO. This is the generic GSSAPI header.

            // [RFC 2743] The use of the Mechanism-Independent Token Format is required for initial context
            // establishment tokens, use in non-initial tokens is optional.

            // skip ApplicationTag 
            tokenBytes = tokenBytes[1..];
            DerEncodingHelper.ReadLength(ref tokenBytes);
            tag = ByteReader.ReadByte(ref tokenBytes);
            if (tag != (byte)DerEncodingTag.ObjectIdentifier) return null;

            var objectIdentifierLength = DerEncodingHelper.ReadLength(ref tokenBytes);
            var objectIdentifier = ByteReader.ReadBytes(ref tokenBytes, objectIdentifierLength);
            if (!ByteUtils.AreByteArraysEqual(objectIdentifier, SPNEGOIdentifier)) return null;

            tag = tokenBytes[0]; // read first byte to figure out type
            if (tag == SimpleProtectedNegotiationTokenInit.NegTokenInitTag)
            {
                // [MS-SPNG] Standard GSS has a strict notion of client (initiator) and server (acceptor).
                // If the client has not sent a negTokenInit ([RFC4178] section 4.2.1) message, no context establishment token is expected from the server.
                // The [NegTokenInit2] SPNEGO extension allows the server to generate a context establishment token message [..] and send it to the client.
                return serverInitiatedNegotiation
                    ? new SimpleProtectedNegotiationTokenInit2(tokenBytes)
                    : new SimpleProtectedNegotiationTokenInit(tokenBytes);
            }

            if (tag == SimpleProtectedNegotiationTokenResponse.NegTokenRespTag)
                return new SimpleProtectedNegotiationTokenResponse(tokenBytes);

            return null;
        }
        else if (tag == SimpleProtectedNegotiationTokenResponse.NegTokenRespTag)
        {
            return new SimpleProtectedNegotiationTokenResponse(tokenBytes);
        }

        return null;
    }
}