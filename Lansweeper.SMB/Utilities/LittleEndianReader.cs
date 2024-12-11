using System.Buffers.Binary;

namespace Lansweeper.Smb.Utilities;

public static class LittleEndianReader
{
    /// <summary>
    /// Reads a little-endian Int16 from the buffer and advances the buffer
    /// </summary>
    /// <param name="buffer"></param>
    /// <returns></returns>
    public static short ReadInt16(ref ReadOnlySpan<byte> buffer)
    {
        return (short)ReadUInt16(ref buffer);
    }


    /// <summary>
    /// Reads a little-endian UInt16 from the buffer and advances the buffer
    /// </summary>
    /// <param name="buffer"></param>
    /// <returns></returns>
    public static ushort ReadUInt16(ref ReadOnlySpan<byte> buffer)
    {
        ushort result = BinaryPrimitives.ReadUInt16LittleEndian(buffer);
        buffer = buffer[2..];
        return result;
    }

    /// <summary>
    /// Reads a little-endian UInt32 from the buffer and advances the buffer
    /// </summary>
    /// <param name="buffer"></param>
    /// <returns></returns>
    public static uint ReadUInt32(ref ReadOnlySpan<byte> buffer)
    {
        uint result = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
        buffer = buffer[4..];
        return result;
    }

    public static ulong ReadUInt64(ref ReadOnlySpan<byte> buffer)
    {
        ulong result = BinaryPrimitives.ReadUInt64LittleEndian(buffer);
        buffer = buffer[8..];
        return result;
    }

    public static DateTime ReadFileTime(ReadOnlySpan<byte> buffer)
    {
        var timeSpan = BinaryPrimitives.ReadInt64LittleEndian(buffer);
        if (timeSpan < 0) throw new InvalidDataException("FILETIME cannot be negative");

        return DateTime.FromFileTimeUtc(timeSpan);
    }

    public static DateTime ReadFileTime(ref ReadOnlySpan<byte> buffer)
    {
        var result = ReadFileTime(buffer);
        buffer = buffer[8..];
        return result;
    }

    public static Guid ReadGuid(ref ReadOnlySpan<byte> dataSpan)
    {
        Guid result =  new(dataSpan[..16], bigEndian: false);
        dataSpan = dataSpan[16..];
        return result;
    }

}