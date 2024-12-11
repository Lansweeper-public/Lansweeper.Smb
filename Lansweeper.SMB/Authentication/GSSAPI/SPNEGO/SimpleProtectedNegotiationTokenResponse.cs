using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;

/// <summary>
///     RFC 4178 - negTokenResp
///     
///  NegTokenResp ::= SEQUENCE {
///      negState       [0] ENUMERATED {
///          accept-completed    (0),
///          accept-incomplete   (1),
///          reject              (2),
///          request-mic         (3)
///      }                                 OPTIONAL,
///        -- REQUIRED in the first reply from the target
///      supportedMech   [1] MechType      OPTIONAL,
///        -- present only in the first reply from the target
///      responseToken   [2] OCTET STRING  OPTIONAL,
///      mechListMIC     [3] OCTET STRING  OPTIONAL,
///      ...
///  }
/// </summary>
public class SimpleProtectedNegotiationTokenResponse : SimpleProtectedNegotiationToken
{
    public const byte NegTokenRespTag = 0xA1;
    public const byte NegStateTag = 0xA0;
    public const byte SupportedMechanismTag = 0xA1;
    public const byte ResponseTokenTag = 0xA2;
    public const byte MechanismListMICTag = 0xA3;
    public byte[]? MechanismListMIC { get; set; } // Optional

    public NegState? NegState { get; set; } // Optional
    public byte[]? ResponseToken { get; set; } // Optional
    public byte[]? SupportedMechanism { get; set; } // Optional

    public SimpleProtectedNegotiationTokenResponse() { }

    /// <param name="offset">The offset following the NegTokenResp tag</param>
    /// <exception cref="InvalidDataException"/>
    public SimpleProtectedNegotiationTokenResponse(ReadOnlySpan<byte> buffer)
    {
        var negTokenRespTag = ByteReader.ReadByte(ref buffer);
        if (negTokenRespTag != NegTokenRespTag) throw new InvalidDataException("Invalid negTokenResp structure");

        DerEncodingHelper.ReadLength(ref buffer); // constructionLength
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.Sequence) throw new InvalidDataException();

        var sequenceLength = DerEncodingHelper.ReadLength(ref buffer);
        buffer = buffer[..sequenceLength];

        while (!buffer.IsEmpty)
        {
            tag = ByteReader.ReadByte(ref buffer);
            if (tag == NegStateTag)
                NegState = ReadNegState(ref buffer);
            else if (tag == SupportedMechanismTag)
                SupportedMechanism = ReadSupportedMechanism(ref buffer);
            else if (tag == ResponseTokenTag)
                ResponseToken = ReadResponseToken(ref buffer);
            else if (tag == MechanismListMICTag)
                MechanismListMIC = ReadMechanismListMIC(ref buffer);
            else
                throw new InvalidDataException("Invalid negTokenResp structure");
        }

    }

    public override byte[] GetBytes()
    {
        var sequenceLength = GetTokenFieldsLength();
        var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
        var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
        var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
        var bufferSize = 1 + constructionLengthFieldSize + 1 + sequenceLengthFieldSize + sequenceLength;
        var buffer = new byte[bufferSize];
        var bufferSpan = buffer.AsSpan();

        ByteWriter.WriteByte(ref bufferSpan, NegTokenRespTag);
        DerEncodingHelper.WriteLength(ref bufferSpan, constructionLength);
        ByteWriter.WriteByte(ref bufferSpan, (byte)DerEncodingTag.Sequence);
        DerEncodingHelper.WriteLength(ref bufferSpan, sequenceLength);
        if (NegState.HasValue) WriteNegState(ref bufferSpan, NegState.Value);
        if (SupportedMechanism is not null) WriteSupportedMechanism(ref bufferSpan, SupportedMechanism);
        if (ResponseToken is not null) WriteResponseToken(ref bufferSpan, ResponseToken);
        if (MechanismListMIC is not null) WriteMechanismListMIC(ref bufferSpan, MechanismListMIC);

        return buffer;
    }

    private int GetTokenFieldsLength()
    {
        var result = 0;
        if (NegState.HasValue)
        {
            var negStateLength = 5;
            result += negStateLength;
        }

        if (SupportedMechanism is not null)
        {
            var supportedMechanismBytesLengthFieldSize =
                DerEncodingHelper.GetLengthFieldSize(SupportedMechanism.Length);
            var supportedMechanismConstructionLength =
                1 + supportedMechanismBytesLengthFieldSize + SupportedMechanism.Length;
            var supportedMechanismConstructionLengthFieldSize =
                DerEncodingHelper.GetLengthFieldSize(supportedMechanismConstructionLength);
            var supportedMechanismLength = 1 + supportedMechanismConstructionLengthFieldSize + 1 +
                                           supportedMechanismBytesLengthFieldSize + SupportedMechanism.Length;
            result += supportedMechanismLength;
        }

        if (ResponseToken is not null)
        {
            var responseTokenBytesLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(ResponseToken.Length);
            var responseTokenConstructionLength = 1 + responseTokenBytesLengthFieldSize + ResponseToken.Length;
            var responseTokenConstructionLengthFieldSize =
                DerEncodingHelper.GetLengthFieldSize(responseTokenConstructionLength);
            var responseTokenLength = 1 + responseTokenConstructionLengthFieldSize + 1 +
                                      responseTokenBytesLengthFieldSize + ResponseToken.Length;
            result += responseTokenLength;
        }

        if (MechanismListMIC is not null)
        {
            var mechanismListMICBytesLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(MechanismListMIC.Length);
            var mechanismListMICConstructionLength = 1 + mechanismListMICBytesLengthFieldSize + MechanismListMIC.Length;
            var mechanismListMICConstructionLengthFieldSize =
                DerEncodingHelper.GetLengthFieldSize(mechanismListMICConstructionLength);
            var responseTokenLength = 1 + mechanismListMICConstructionLengthFieldSize + 1 +
                                      mechanismListMICBytesLengthFieldSize + MechanismListMIC.Length;
            result += responseTokenLength;
        }

        return result;
    }

    /// <exception cref="InvalidDataException"/>
    private static NegState ReadNegState(ref ReadOnlySpan<byte> buffer)
    {
        DerEncodingHelper.ReadLength(ref buffer);
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.Enum) throw new InvalidDataException();

        DerEncodingHelper.ReadLength(ref buffer);
        return (NegState)ByteReader.ReadByte(ref buffer);
    }

    /// <exception cref="InvalidDataException"/>
    private static byte[] ReadSupportedMechanism(ref ReadOnlySpan<byte> buffer)
    {
        DerEncodingHelper.ReadLength(ref buffer);
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.ObjectIdentifier) throw new InvalidDataException();

        var length = DerEncodingHelper.ReadLength(ref buffer);
        return ByteReader.ReadBytes(ref buffer, length);
    }

    /// <exception cref="InvalidDataException"/>
    private static byte[] ReadResponseToken(ref ReadOnlySpan<byte> buffer)
    {
        DerEncodingHelper.ReadLength(ref buffer);
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.ByteArray) throw new InvalidDataException();

        var length = DerEncodingHelper.ReadLength(ref buffer);
        return ByteReader.ReadBytes(ref buffer, length);
    }

    /// <exception cref="InvalidDataException"/>
#pragma warning disable S4144 // Methods should not have identical implementations, this method is prone to change
    private static byte[] ReadMechanismListMIC(ref ReadOnlySpan<byte> buffer)
    {
        DerEncodingHelper.ReadLength(ref buffer);
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.ByteArray) throw new InvalidDataException();

        var length = DerEncodingHelper.ReadLength(ref buffer);
        return ByteReader.ReadBytes(ref buffer, length);
    }
#pragma warning restore S4144 // Methods should not have identical implementations

    private static void WriteNegState(ref Span<byte> buffer, NegState negState)
    {
        ByteWriter.WriteByte(ref buffer, NegStateTag);
        DerEncodingHelper.WriteLength(ref buffer, 3);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.Enum);
        DerEncodingHelper.WriteLength(ref buffer, 1);
        ByteWriter.WriteByte(ref buffer, (byte)negState);
    }

    private static void WriteSupportedMechanism(ref Span<byte> buffer, byte[] supportedMechanism)
    {
        var supportedMechanismLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(supportedMechanism.Length);
        ByteWriter.WriteByte(ref buffer, SupportedMechanismTag);
        DerEncodingHelper.WriteLength(ref buffer, 1 + supportedMechanismLengthFieldSize + supportedMechanism.Length);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.ObjectIdentifier);
        DerEncodingHelper.WriteLength(ref buffer, supportedMechanism.Length);
        ByteWriter.WriteBytes(ref buffer, supportedMechanism);
    }

    private static void WriteResponseToken(ref Span<byte> buffer, byte[] responseToken)
    {
        var responseTokenLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(responseToken.Length);
        ByteWriter.WriteByte(ref buffer, ResponseTokenTag);
        DerEncodingHelper.WriteLength(ref buffer, 1 + responseTokenLengthFieldSize + responseToken.Length);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.ByteArray);
        DerEncodingHelper.WriteLength(ref buffer, responseToken.Length);
        ByteWriter.WriteBytes(ref buffer, responseToken);
    }

    private static void WriteMechanismListMIC(ref Span<byte> buffer, byte[] mechanismListMIC)
    {
        var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismListMIC.Length);
        ByteWriter.WriteByte(ref buffer, MechanismListMICTag);
        DerEncodingHelper.WriteLength(ref buffer, 1 + mechanismListMICLengthFieldSize + mechanismListMIC.Length);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.ByteArray);
        DerEncodingHelper.WriteLength(ref buffer, mechanismListMIC.Length);
        ByteWriter.WriteBytes(ref buffer, mechanismListMIC);
    }
}