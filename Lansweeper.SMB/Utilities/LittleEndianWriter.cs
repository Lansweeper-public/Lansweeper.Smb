using System.Buffers.Binary;

namespace Lansweeper.Smb.Utilities;

public static class LittleEndianWriter
{
    public static void WriteInt16(Stream stream, short value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteInt16LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    public static void WriteInt16(Span<byte> buffer, short value)
    { 
        BinaryPrimitives.WriteInt16LittleEndian(buffer, value);
    }

    public static void WriteInt16(ref Span<byte> buffer, short value)
    {
        WriteInt16(buffer, value);
        buffer = buffer[2..];
    }

    public static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    public static void WriteUInt16(Span<byte> buffer, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
    }

    public static void WriteUInt16(ref Span<byte> buffer, ushort value)
    {
        WriteUInt16(buffer, value);
        buffer = buffer[2..];
    }

    public static void WriteInt32(Stream stream, int value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    public static void WriteInt32(Span<byte> buffer, int value)
    {
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
    }

    public static void WriteInt32(ref Span<byte> buffer, int value)
    {
        WriteInt32(buffer, value);
        buffer = buffer[4..];
    }

    public static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    public static void WriteUInt32(Span<byte> buffer, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
    }

    public static void WriteUInt32(ref Span<byte> buffer, uint value)
    {
        WriteUInt32(buffer, value);
        buffer = buffer[4..];
    }

    public static void WriteInt64(Stream stream, long value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    public static void WriteInt64(Span<byte> buffer, long value)
    {
        BinaryPrimitives.WriteInt64LittleEndian(buffer, value);
    }

    public static void WriteInt64(ref Span<byte> buffer, long value)
    {
        WriteInt64(buffer, value);
        buffer = buffer[8..];
    }

    public static void WriteUInt64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    public static void WriteUInt64(Span<byte> buffer, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
    }

    public static void WriteUInt64(ref Span<byte> buffer, ulong value)
    {
        WriteUInt64(buffer, value);
        buffer = buffer[8..];
    }
    public static void WriteGuid(Span<byte> buffer, Guid value)
    {
        var bytes = value.ToByteArray(bigEndian: false);
        bytes.CopyTo(buffer);
    }

    public static void WriteGuid(ref Span<byte> buffer, Guid value)
    {
        WriteGuid(buffer, value);
        buffer = buffer[16..];
    }

    public static void WriteFileTime(Span<byte> buffer, DateTime value)
    {
        BinaryPrimitives.WriteInt64LittleEndian(buffer, value.ToFileTimeUtc());
    }

    public static void WriteFileTime(ref Span<byte> buffer, DateTime value)
    {
        WriteFileTime(buffer, value);
        buffer = buffer[8..];
    }

}