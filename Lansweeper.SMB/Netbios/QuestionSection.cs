using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.2.1.2. QUESTION SECTION
///     
///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                                                               |
///    /                         QUESTION_NAME                         /
///    /                                                               /
///    |                                                               |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |         QUESTION_TYPE         |        QUESTION_CLASS         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class QuestionSection
{
    public QuestionClass Class { get; set; }
    public string Name { get; set; }
    public NameRecordType Type { get; set; }

    public QuestionSection(NameRecordType type, string name)
    {
        Class = QuestionClass.In;
        Type = type;
        Name = name;
    }

    public QuestionSection(ReadOnlySpan<byte> buffer)
    {
        Name = NetBiosUtils.DecodeName(ref buffer);
        Type = (NameRecordType)BigEndianReader.ReadUInt16(ref buffer);
        Class = (QuestionClass)BigEndianReader.ReadUInt16(ref buffer);
    }

    public void WriteBytes(Stream stream)
    {
        var encodedName = NetBiosUtils.EncodeName(Name, string.Empty);
        ByteWriter.WriteBytes(stream, encodedName);
        BigEndianWriter.WriteUInt16(stream, (ushort)Type);
        BigEndianWriter.WriteUInt16(stream, (ushort)Class);
    }
}