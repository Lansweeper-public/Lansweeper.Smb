using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;

/// <summary>
///     [MS-SPNG] - NegTokenInit2
///     
///  NegHints ::= SEQUENCE {
///   hintName[0] GeneralString OPTIONAL,
///   hintAddress[1] OCTET STRING OPTIONAL
///  }
///  NegTokenInit2::= SEQUENCE {
///      mechTypes[0] MechTypeList OPTIONAL,
///      reqFlags[1] ContextFlags OPTIONAL,
///      mechToken[2] OCTET STRING OPTIONAL,
///   negHints[3] NegHints OPTIONAL,
///   mechListMIC[4] OCTET STRING OPTIONAL,
///   ...
///  }
/// </summary>
public class SimpleProtectedNegotiationTokenInit2 : SimpleProtectedNegotiationTokenInit
{
    public const byte NegHintsTag = 0xA3;
    public new const byte MechanismListMICTag = 0xA4;
    public const byte HintNameTag = 0xA0;
    public const byte HintAddressTag = 0xA1;

    public byte[]? HintAddress { get;set; }
    public string? HintName { get; set; }

    public SimpleProtectedNegotiationTokenInit2()
    {
        HintName = "not_defined_in_RFC4178@please_ignore";
    }

    public SimpleProtectedNegotiationTokenInit2(ReadOnlySpan<byte> buffer)
    {
        var negTokenInitTag = ByteReader.ReadByte(ref buffer);
        if (negTokenInitTag != NegTokenInitTag) throw new InvalidDataException("Invalid negTokenInit2 structure");

        DerEncodingHelper.ReadLength(ref buffer); // constructionLength
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.Sequence) throw new InvalidDataException();

        var sequenceLength = DerEncodingHelper.ReadLength(ref buffer);
        buffer = buffer[..sequenceLength];

        while (!buffer.IsEmpty)
        {
            tag = ByteReader.ReadByte(ref buffer);
            if (tag == MechanismTypeListTag)
                MechanismTypeList = ReadMechanismTypeList(ref buffer);
            else if (tag == RequiredFlagsTag)
                throw new NotImplementedException("negTokenInit.ReqFlags is not implemented");
            else if (tag == MechanismTokenTag)
                MechanismToken = ReadMechanismToken(ref buffer);
            else if (tag == NegHintsTag)
                (HintName, HintAddress) = ReadHints(ref buffer);
            else if (tag == MechanismListMICTag)
                MechanismListMIC = ReadMechanismListMIC(ref buffer);
            else
                throw new InvalidDataException("Invalid negTokenInit structure");
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

        ByteWriter.WriteByte(ref bufferSpan, NegTokenInitTag);
        DerEncodingHelper.WriteLength(ref bufferSpan, constructionLength);
        ByteWriter.WriteByte(ref bufferSpan, (byte)DerEncodingTag.Sequence);
        DerEncodingHelper.WriteLength(ref bufferSpan, sequenceLength);

        if (MechanismTypeList is not null) WriteMechanismTypeList(ref bufferSpan, MechanismTypeList);
        if (MechanismToken is not null) WriteMechanismToken(ref bufferSpan, MechanismToken);
        if (HintName is not null || HintAddress is not null) WriteHints(ref bufferSpan, HintName, HintAddress);
        if (MechanismListMIC is not null) WriteMechanismListMIC(ref bufferSpan, MechanismListMIC);

        return buffer;
    }

    protected override int GetTokenFieldsLength()
    {
        var result = base.GetTokenFieldsLength();
        
        if (HintName is not null || HintAddress is not null)
        {
            var hintsSequenceLength = GetHintsSequenceLength(HintName, HintAddress);
            var hintsSequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintsSequenceLength);
            var hintsSequenceConstructionLength = 1 + hintsSequenceLengthFieldSize + hintsSequenceLength;
            var hintsSequenceConstructionLengthFieldSize =
                DerEncodingHelper.GetLengthFieldSize(hintsSequenceConstructionLength);
            var entryLength = 1 + hintsSequenceConstructionLengthFieldSize + 1 + hintsSequenceLengthFieldSize +
                              hintsSequenceLength;
            result += entryLength;
        }

        return result;
    }

    /// <exception cref="InvalidDataException"/>
    protected static (string? hintName, byte[]? hintAddress) ReadHints(ref ReadOnlySpan<byte> buffer)
    {
        string? hintName = null;
        byte[]? hintAddress = null;
        DerEncodingHelper.ReadLength(ref buffer); // constructionLength
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.Sequence) throw new InvalidDataException();

        var sequenceLength = DerEncodingHelper.ReadLength(ref buffer);
        buffer = buffer[..sequenceLength];

        while (!buffer.IsEmpty)
        {
            tag = ByteReader.ReadByte(ref buffer);
            if (tag == HintNameTag)
                hintName = ReadHintName(ref buffer);
            else if (tag == HintAddressTag)
                hintAddress = ReadHintAddress(ref buffer);
            else
                throw new InvalidDataException();
        }

        return (hintName, hintAddress);
    }

    /// <exception cref="InvalidDataException"/>
    protected static string ReadHintName(ref ReadOnlySpan<byte> buffer)
    {
        DerEncodingHelper.ReadLength(ref buffer); // constructionLength
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.GeneralString) throw new InvalidDataException();

        var hintLength = DerEncodingHelper.ReadLength(ref buffer);
        var hintNameBytes = ByteReader.ReadBytes(ref buffer, hintLength);
        return DerEncodingHelper.DecodeGeneralString(hintNameBytes);
    }

    /// <exception cref="InvalidDataException"/>
    protected static byte[] ReadHintAddress(ref ReadOnlySpan<byte> buffer)
    {
        DerEncodingHelper.ReadLength(ref buffer); // constructionLength
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.ByteArray) throw new InvalidDataException();

        var hintLength = DerEncodingHelper.ReadLength(ref buffer);
        return ByteReader.ReadBytes(ref buffer, hintLength);
    }

    protected static int GetHintsSequenceLength(string? hintName, byte[]? hintAddress)
    {
        var sequenceLength = 0;
        if (hintName is not null)
        {
            var hintNameBytes = DerEncodingHelper.EncodeGeneralString(hintName);
            var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintNameBytes.Length);
            var constructionLength = 1 + lengthFieldSize + hintNameBytes.Length;
            var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
            var entryLength = 1 + constructionLengthFieldSize + 1 + lengthFieldSize + hintNameBytes.Length;
            sequenceLength += entryLength;
        }

        if (hintAddress is not null)
        {
            var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintAddress.Length);
            var constructionLength = 1 + lengthFieldSize + hintAddress.Length;
            var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
            var entryLength = 1 + constructionLengthFieldSize + 1 + lengthFieldSize + hintAddress.Length;
            sequenceLength += entryLength;
        }

        return sequenceLength;
    }

    private static void WriteHints(ref Span<byte> buffer, string? hintName, byte[]? hintAddress)
    {
        var sequenceLength = GetHintsSequenceLength(hintName, hintAddress);
        var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
        var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
        ByteWriter.WriteByte(ref buffer, NegHintsTag);
        DerEncodingHelper.WriteLength(ref buffer, constructionLength);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.Sequence);
        DerEncodingHelper.WriteLength(ref buffer, sequenceLength);
        if (hintName is not null) WriteHintName(ref buffer, hintName);
        if (hintAddress is not null) WriteHintAddress(ref buffer, hintAddress);
    }

    private static void WriteHintName(ref Span<byte> buffer, string hintName)
    {
        var hintNameBytes = DerEncodingHelper.EncodeGeneralString(hintName);
        var constructionLength = 1 + DerEncodingHelper.GetLengthFieldSize(hintNameBytes.Length) + hintNameBytes.Length;
        ByteWriter.WriteByte(ref buffer, HintNameTag);
        DerEncodingHelper.WriteLength(ref buffer, constructionLength);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.GeneralString);
        DerEncodingHelper.WriteLength(ref buffer, hintNameBytes.Length);
        ByteWriter.WriteBytes(ref buffer, hintNameBytes);
    }

    private static void WriteHintAddress(ref Span<byte> buffer, byte[] hintAddress)
    {
        var constructionLength = 1 + DerEncodingHelper.GetLengthFieldSize(hintAddress.Length) + hintAddress.Length;
        ByteWriter.WriteByte(ref buffer, HintAddressTag);
        DerEncodingHelper.WriteLength(ref buffer, constructionLength);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.ByteArray);
        DerEncodingHelper.WriteLength(ref buffer, hintAddress.Length);
        ByteWriter.WriteBytes(ref buffer, hintAddress);
    }

    protected new static void WriteMechanismListMIC(ref Span<byte> buffer, byte[] mechanismListMIC)
    {
        var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismListMIC.Length);
        ByteWriter.WriteByte(ref buffer, MechanismListMICTag);
        DerEncodingHelper.WriteLength(ref buffer,
            1 + mechanismListMICLengthFieldSize + mechanismListMIC.Length);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.ByteArray);
        DerEncodingHelper.WriteLength(ref buffer, mechanismListMIC.Length);
        ByteWriter.WriteBytes(ref buffer, mechanismListMIC);
    }
}