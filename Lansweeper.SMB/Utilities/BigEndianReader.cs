using System.Buffers.Binary;

namespace Lansweeper.Smb.Utilities;

public static class BigEndianReader
{
    /// <summary>
    /// Reads a big-endian UInt16 from the buffer and advances the buffer
    /// </summary>
    public static ushort ReadUInt16(ref ReadOnlySpan<byte> buffer)
    {
        ushort result = BinaryPrimitives.ReadUInt16BigEndian(buffer);
        buffer = buffer[2..];
        return result;
    }

    /// <summary>
    /// Reads a big-endian UInt32 from the buffer and advances the buffer
    /// </summary>
    public static uint ReadUInt32(ref ReadOnlySpan<byte> buffer)
    {
        uint result = BinaryPrimitives.ReadUInt32BigEndian(buffer);
        buffer = buffer[4..];
        return result;
    }

    /// <summary>
    /// Reads a big-endian GUID from the buffer and advances the buffer
    /// </summary>
    public static Guid ReadGuid(ref ReadOnlySpan<byte> dataSpan)
    {
        Guid result = new(dataSpan[..16], bigEndian: true);
        dataSpan = dataSpan[16..];
        return result;
    }

}