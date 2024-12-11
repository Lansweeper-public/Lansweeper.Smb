using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.2.1.3. RESOURCE RECORD
///     
///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                                                               |
///    /                            RR_NAME                            /
///    /                                                               /
///    |                                                               |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |           RR_TYPE             |          RR_CLASS             |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                              TTL                              |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |           RDLENGTH            |                               |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
///    /                                                               /
///    /                             RDATA                             /
///    |                                                               |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class ResourceRecord
{
    public string Name { get; }
    public NameRecordType Type { get; }
    public ResourceRecordClass Class { get; }
    public uint TTL { get; set; }
    public byte[] Data { get; set; }

    public ResourceRecord(NameRecordType type, string? name = null)
    {
        Name = name ?? string.Empty;
        Type = type;
        Class = ResourceRecordClass.In;
        TTL = (uint)new TimeSpan(7, 0, 0, 0).TotalSeconds;
        Data = [];
    }

    public ResourceRecord(ReadOnlySpan<byte> buffer)
    {
        Name = NetBiosUtils.DecodeName(ref buffer);
        Type = (NameRecordType)BigEndianReader.ReadUInt16(ref buffer);
        Class = (ResourceRecordClass)BigEndianReader.ReadUInt16(ref buffer);
        TTL = BigEndianReader.ReadUInt32(ref buffer);
        var dataLength = BigEndianReader.ReadUInt16(ref buffer);
        Data = ByteReader.ReadBytes(ref buffer, dataLength);
    }

    public void WriteBytes(Stream stream, int? nameOffset = null)
    {
        if (nameOffset.HasValue)
        {
            NetBiosUtils.WriteNamePointer(stream, nameOffset.Value);
        }
        else
        {
            var encodedName = NetBiosUtils.EncodeName(Name, string.Empty);
            ByteWriter.WriteBytes(stream, encodedName);
        }

        BigEndianWriter.WriteUInt16(stream, (ushort)Type);
        BigEndianWriter.WriteUInt16(stream, (ushort)Class);
        BigEndianWriter.WriteUInt32(stream, TTL);
        BigEndianWriter.WriteUInt16(stream, (ushort)Data.Length);
        ByteWriter.WriteBytes(stream, Data);
    }
}