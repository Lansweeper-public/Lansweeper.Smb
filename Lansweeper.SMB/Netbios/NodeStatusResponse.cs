using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.2.18. NODE STATUS RESPONSE
/// 
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         NAME_TRN_ID           |1|  0x0  |1|0|0|0|0|0|0|  0x0  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          0x0000               |           0x0001              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          0x0000               |           0x0000              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                            RR_NAME                            /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |        NBSTAT(0x0021)        |         IN(0x0001)           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          0x00000000                           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          RDLENGTH             |   NUM_NAMES   |               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
///   |                                                               |
///   +                                                               +
///   /                         NODE_NAME ARRAY                       /
///   +                                                               +
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   +                                                               +
///   /                           STATISTICS                          /
///   +                                                               +
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class NodeStatusResponse
{
    public NameServicePacketHeader Header { get; }

    // Resource Data:
    public KeyValuePairList<string, NameFlags> Names { get; } = [];
    public ResourceRecord Resource { get; }
    public NodeStatistics Statistics { get; }

    public NodeStatusResponse(ushort transactionId, string name)
    {
        Header = new NameServicePacketHeader
        {
            TransactionID = transactionId,
            OpCode = NameServiceOperation.QueryResponse,
            Flags = OperationFlags.AuthoritativeAnswer,
            ANCount = 1,
        };
        Resource = new ResourceRecord(NameRecordType.NBStat, name);
        Statistics = new NodeStatistics();
    }

    public NodeStatusResponse(ReadOnlySpan<byte> buffer)
    {
        Header = new NameServicePacketHeader(buffer);
        Resource = new ResourceRecord(buffer[NameServicePacketHeader.Length..]);

        ReadOnlySpan<byte> span = Resource.Data;
        var numberOfNames = ByteReader.ReadByte(ref span);
        for (int index = 0; index < numberOfNames; index++)
        {
            var name = ByteReader.ReadAnsiString(ref span, 16);
            NameFlags nameFlags = new(span);
            span = span[2..];
            Names.Add(name, nameFlags);
        }

        Statistics = new NodeStatistics(span);
    }

    public byte[] GetBytes()
    {
        Resource.Data = GetData();

        using var stream = new MemoryStream();
        Header.WriteBytes(stream);
        Resource.WriteBytes(stream);
        return stream.ToArray();
    }

    private byte[] GetData()
    {
        using var stream = new MemoryStream();
        stream.WriteByte((byte)Names.Count);
        foreach (var entry in Names)
        {
            ByteWriter.WriteAnsiString(stream, entry.Key);
            entry.Value.WriteBytes(stream);
        }

        ByteWriter.WriteBytes(stream, Statistics.GetBytes());

        return stream.ToArray();
    }
}