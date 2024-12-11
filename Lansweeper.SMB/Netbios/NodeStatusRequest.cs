using Lansweeper.Smb.Netbios.Enums;
using System.Security.Cryptography;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.2.17. NODE STATUS REQUEST
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         NAME_TRN_ID           |0|  0x0  |0|0|0|0|0 0|B|  0x0  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          0x0001               |           0x0000              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          0x0000               |           0x0000              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                         QUESTION_NAME                         /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         NBSTAT(0x0021)       |        IN(0x0001)            |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class NodeStatusRequest
{
    public NameServicePacketHeader Header { get; }
    public QuestionSection Question { get; }

    /// <remarks>
    /// currently only implements unicast case
    /// </remarks>
    public NodeStatusRequest(string questionName)
    {
        Header = new NameServicePacketHeader
        {
            TransactionID = (ushort)RandomNumberGenerator.GetInt32(1, 65536), // 0 is not recommended
            OpCode = NameServiceOperation.QueryRequest,
            QDCount = 1,
        };
        Question = new QuestionSection(NameRecordType.NBStat, questionName);
    }

    public NodeStatusRequest(ReadOnlySpan<byte> buffer)
    {
        Header = new NameServicePacketHeader(buffer);
        Question = new QuestionSection(buffer[NameServicePacketHeader.Length..]);
    }

    public byte[] GetBytes()
    {
        using var stream = new MemoryStream();
        Header.WriteBytes(stream);
        Question.WriteBytes(stream);
        return stream.ToArray();
    }
}

