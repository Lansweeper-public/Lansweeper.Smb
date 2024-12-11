using System.Buffers.Binary;

namespace Lansweeper.Smb.Utilities;

public static class BigEndianWriter
{
    /// <summary>
    /// Takes a span, writes a ushort to it and advances the span
    /// </summary>
    /// <param name="buffer"></param>
    /// <param name="value"></param>
    public static void WriteUInt16(ref Span<byte> buffer, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
        buffer = buffer[2..];
    }

    public static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> valueAsBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(valueAsBytes, value);
        stream.Write(valueAsBytes);
    }

    /// <summary>
    /// Takes a span, writes a uint to it and advances the span
    /// </summary>
    /// <param name="buffer"></param>
    /// <param name="value"></param>
    public static void WriteUInt32(ref Span<byte> buffer, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        buffer = buffer[4..];
    }

    public static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> valueAsBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(valueAsBytes, value);
        stream.Write(valueAsBytes);
    }

    internal static void WriteGuid(Span<byte> buffer, Guid value)
    {
        var bytes = value.ToByteArray(bigEndian: true);
        bytes.CopyTo(buffer);
    }

    public static void WriteGuid(ref Span<byte> buffer, Guid value)
    {
        WriteGuid(buffer, value);
        buffer = buffer[16..];
    }
}