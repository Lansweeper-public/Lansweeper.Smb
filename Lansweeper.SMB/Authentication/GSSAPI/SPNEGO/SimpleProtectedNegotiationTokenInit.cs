using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;

/// <summary>
///     RFC 4178 - negTokenInit
///     
/// NegTokenInit ::= SEQUENCE {
///     mechTypes[0] MechTypeList,
///     reqFlags[1] ContextFlags OPTIONAL,
///       -- inherited from RFC 2478 for backward compatibility,
///       -- RECOMMENDED to be left out
///     mechToken[2] OCTET STRING OPTIONAL,
///     mechListMIC[3] OCTET STRING  OPTIONAL,
///     ...
/// }
/// ContextFlags::= BIT STRING {
///     delegFlag       (0),
///     mutualFlag      (1),
///     replayFlag      (2),
///     sequenceFlag    (3),
///     anonFlag        (4),
///     confFlag        (5),
///     integFlag       (6)
/// } (SIZE(32))
/// </summary>
public class SimpleProtectedNegotiationTokenInit : SimpleProtectedNegotiationToken
{
    public const byte NegTokenInitTag = 0xA0;
    public const byte MechanismTypeListTag = 0xA0;
    public const byte RequiredFlagsTag = 0xA1;
    public const byte MechanismTokenTag = 0xA2;
    public const byte MechanismListMICTag = 0xA3;

    public byte[]? MechanismListMIC { get; set; } // Optional

    // reqFlags - Optional, RECOMMENDED to be left out
    public byte[]? MechanismToken { get; set; } // Optional

    /// <summary>
    ///     Contains one or more security mechanisms available for the initiator, in decreasing preference order.
    /// </summary>
    public List<byte[]>? MechanismTypeList { get; set; } // Optional

    public SimpleProtectedNegotiationTokenInit() { }

    /// <param name="offset">The offset following the NegTokenInit tag</param>
    /// <exception cref="InvalidDataException"/>
    public SimpleProtectedNegotiationTokenInit(ReadOnlySpan<byte> buffer)
    {
        var negTokenInitTag = ByteReader.ReadByte(ref buffer);
        if (negTokenInitTag != NegTokenInitTag) throw new InvalidDataException("Invalid negTokenInit structure");


        DerEncodingHelper.ReadLength(ref buffer); //constructionLength
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
        if (MechanismListMIC is not null) WriteMechanismListMIC(ref bufferSpan, MechanismListMIC);

        return buffer;
    }

    protected virtual int GetTokenFieldsLength()
    {
        var result = GetEncodedMechanismTypeListLength(MechanismTypeList);
        if (MechanismToken is not null)
        {
            var mechanismTokenLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(MechanismToken.Length);
            var mechanismTokenConstructionLength = 1 + mechanismTokenLengthFieldSize + MechanismToken.Length;
            var mechanismTokenConstructionLengthFieldSize =
                DerEncodingHelper.GetLengthFieldSize(mechanismTokenConstructionLength);
            var entryLength = 1 + mechanismTokenConstructionLengthFieldSize + 1 + mechanismTokenLengthFieldSize +
                              MechanismToken.Length;
            result += entryLength;
        }

        if (MechanismListMIC is not null)
        {
            var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(MechanismListMIC.Length);
            var mechanismListMICConstructionLength = 1 + mechanismListMICLengthFieldSize + MechanismListMIC.Length;
            var mechanismListMICConstructionLengthFieldSize =
                DerEncodingHelper.GetLengthFieldSize(mechanismListMICConstructionLength);
            var entryLength = 1 + mechanismListMICConstructionLengthFieldSize + 1 + mechanismListMICLengthFieldSize +
                              MechanismListMIC.Length;
            result += entryLength;
        }

        return result;
    }

    /// <exception cref="InvalidDataException"/>
    protected static List<byte[]> ReadMechanismTypeList(ref ReadOnlySpan<byte> buffer)
    {
        var result = new List<byte[]>();
        DerEncodingHelper.ReadLength(ref buffer); //constructionLength
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.Sequence) throw new InvalidDataException();

        var sequenceLength = DerEncodingHelper.ReadLength(ref buffer);
        var mechanismListSpan = buffer[..sequenceLength];

        while (!mechanismListSpan.IsEmpty)
        {
            tag = ByteReader.ReadByte(ref mechanismListSpan);
            if (tag != (byte)DerEncodingTag.ObjectIdentifier) throw new InvalidDataException();

            var mechanismTypeLength = DerEncodingHelper.ReadLength(ref mechanismListSpan);
            var mechanismType = ByteReader.ReadBytes(ref mechanismListSpan, mechanismTypeLength);
            result.Add(mechanismType);
        }

        buffer = buffer[sequenceLength..];
        return result;
    }

    /// <exception cref="InvalidDataException"/>
    protected static byte[] ReadMechanismToken(ref ReadOnlySpan<byte> buffer)
    {
        DerEncodingHelper.ReadLength(ref buffer); //constructionLength
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.ByteArray) throw new InvalidDataException();

        var mechanismTokenLength = DerEncodingHelper.ReadLength(ref buffer);
        var token = ByteReader.ReadBytes(ref buffer, mechanismTokenLength);
        return token;
    }

    protected static byte[] ReadMechanismListMIC(ref ReadOnlySpan<byte> buffer)
    {
        DerEncodingHelper.ReadLength(ref buffer); //constructionLength
        var tag = ByteReader.ReadByte(ref buffer);
        if (tag != (byte)DerEncodingTag.ByteArray) throw new InvalidDataException();

        var mechanismListMICLength = DerEncodingHelper.ReadLength(ref buffer);
        var mechanismListMIC = ByteReader.ReadBytes(ref buffer, mechanismListMICLength);
        return mechanismListMIC;
    }

    protected static int GetMechanismTypeListSequenceLength(List<byte[]> mechanismTypeList)
    {
        var sequenceLength = 0;
#pragma warning disable S3267 // Loops should be simplified with "LINQ" expressions
        foreach (var mechanismType in mechanismTypeList)
        {
            var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismType.Length);
            var entryLength = 1 + lengthFieldSize + mechanismType.Length;
            sequenceLength += entryLength;
        }
#pragma warning restore S3267 // Loops should be simplified with "LINQ" expressions

        return sequenceLength;
    }

    protected static void WriteMechanismTypeList(ref Span<byte> buffer, List<byte[]> mechanismTypeList)
    {
        var sequenceLength = GetMechanismTypeListSequenceLength(mechanismTypeList);
        var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
        var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
        ByteWriter.WriteByte(ref buffer, MechanismTypeListTag);
        DerEncodingHelper.WriteLength(ref buffer, constructionLength);
        WriteMechanismTypeListSequence(ref buffer, mechanismTypeList, sequenceLength);
    }

    protected static void WriteMechanismTypeListSequence(ref Span<byte> buffer, List<byte[]> mechanismTypeList,
    int sequenceLength)
    {
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.Sequence);
        DerEncodingHelper.WriteLength(ref buffer, sequenceLength);
        foreach (var mechanismType in mechanismTypeList)
        {
            ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.ObjectIdentifier);
            DerEncodingHelper.WriteLength(ref buffer, mechanismType.Length);
            ByteWriter.WriteBytes(ref buffer, mechanismType);
        }
    }

    protected static void WriteMechanismToken(ref Span<byte> buffer, byte[] mechanismToken)
    {
        var constructionLength =
            1 + DerEncodingHelper.GetLengthFieldSize(mechanismToken.Length) + mechanismToken.Length;
        ByteWriter.WriteByte(ref buffer, MechanismTokenTag);
        DerEncodingHelper.WriteLength(ref buffer, constructionLength);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.ByteArray);
        DerEncodingHelper.WriteLength(ref buffer, mechanismToken.Length);
        ByteWriter.WriteBytes(ref buffer, mechanismToken);
    }

    protected static void WriteMechanismListMIC(ref Span<byte> buffer, byte[] mechanismListMIC)
    {
        var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismListMIC.Length);
        ByteWriter.WriteByte(ref buffer, MechanismListMICTag);
        DerEncodingHelper.WriteLength(ref buffer, 1 + mechanismListMICLengthFieldSize + mechanismListMIC.Length);
        ByteWriter.WriteByte(ref buffer, (byte)DerEncodingTag.ByteArray);
        DerEncodingHelper.WriteLength(ref buffer, mechanismListMIC.Length);
        ByteWriter.WriteBytes(ref buffer, mechanismListMIC);
    }


    public static byte[] GetMechanismTypeListBytes(List<byte[]> mechanismTypeList)
    {
        var sequenceLength = GetMechanismTypeListSequenceLength(mechanismTypeList);
        var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
        var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
        var buffer = new byte[constructionLength];
        var bufferSpan = buffer.AsSpan();
        WriteMechanismTypeListSequence(ref bufferSpan, mechanismTypeList, sequenceLength);
        return buffer;
    }

    private static int GetEncodedMechanismTypeListLength(List<byte[]>? mechanismTypeList)
    {
        if (mechanismTypeList is null) return 0;

        var typeListSequenceLength = GetMechanismTypeListSequenceLength(mechanismTypeList);
        var typeListSequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(typeListSequenceLength);
        var typeListConstructionLength = 1 + typeListSequenceLengthFieldSize + typeListSequenceLength;
        var typeListConstructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(typeListConstructionLength);
        return 1 + typeListConstructionLengthFieldSize + 1 + typeListSequenceLengthFieldSize + typeListSequenceLength;
    }
}