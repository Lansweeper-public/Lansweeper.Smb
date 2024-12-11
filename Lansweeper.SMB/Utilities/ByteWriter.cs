using System.Text;

namespace Lansweeper.Smb.Utilities;

public static class ByteWriter
{
    public static void WriteByte(Span<byte> buffer, byte value)
    {
        buffer[0] = value;
    }

    public static void WriteByte(ref Span<byte> buffer, byte value)
    {
        buffer[0] = value;
        buffer = buffer[1..];
    }

    public static void WriteBytes(Span<byte> buffer, ReadOnlySpan<byte> bytes)
    {
        bytes.CopyTo(buffer);
    }

    public static void WriteBytes(ref Span<byte> buffer, ReadOnlySpan<byte> bytes)
    {
        WriteBytes(buffer, bytes);
        buffer = buffer[bytes.Length..];
    }

    public static void WriteBytes(Stream stream, byte[] bytes)
    {
        stream.Write(bytes, 0, bytes.Length);
    }

    public static void WriteBytes(Stream stream, byte[] bytes, int count)
    {
        stream.Write(bytes, 0, count);
    }

    public static void WriteAnsiString(Stream stream, string value)
    {
        WriteAnsiString(stream, value, value.Length);
    }

    public static void WriteAnsiString(Stream stream, string value, int fieldLength)
    {
        var bytes = Encoding.GetEncoding(28591).GetBytes(value);
        stream.Write(bytes, 0, Math.Min(bytes.Length, fieldLength));
        if (bytes.Length < fieldLength)
        {
            var zeroFill = new byte[fieldLength - bytes.Length];
            stream.Write(zeroFill, 0, zeroFill.Length);
        }
    }

    public static void WriteAnsiString(Span<byte> buffer, string value, int maximumNumberOfCharacters)
    {
        Encoding.GetEncoding(28591).GetBytes(value.AsSpan(0, maximumNumberOfCharacters), buffer);
    }

    public static void WriteAnsiString(ref Span<byte> buffer, string value, int maximumNumberOfCharacters)
    {
        WriteAnsiString(buffer, value, maximumNumberOfCharacters);
        buffer = buffer[maximumNumberOfCharacters..];
    }

    public static void WriteAnsiString(Span<byte> buffer, string value)
    {
        Encoding.GetEncoding(28591).GetBytes(value, buffer);
    }

    public static void WriteAnsiString(ref Span<byte> buffer, string value)
    {
        WriteAnsiString(buffer, value);
        buffer = buffer[value.Length..];
    }

    public static void WriteUTF16String(Stream stream, string value)
    {
        var bytes = Encoding.Unicode.GetBytes(value);
        stream.Write(bytes, 0, bytes.Length);
    }

    public static void WriteUTF16String(Span<byte> buffer, string value, int maximumNumberOfCharacters)
    { 
        Encoding.Unicode.GetBytes(value.AsSpan(0, maximumNumberOfCharacters), buffer);
    }

    public static void WriteUTF16String(ref Span<byte> buffer, string value, int maximumNumberOfCharacters)
    {
        WriteUTF16String(buffer, value, maximumNumberOfCharacters);
        buffer = buffer[(maximumNumberOfCharacters * 2)..];
    }

    public static void WriteUTF16String(Span<byte> buffer, string value)
    {
        Encoding.Unicode.GetBytes(value, buffer);
    }

    public static void WriteUTF16String(ref Span<byte> buffer, string value)
    {
        WriteUTF16String(buffer, value);
        buffer = buffer[(value.Length * 2)..];
    }

    public static void WriteNullTerminatedAnsiString(Span<byte> buffer, string value)
    {
        WriteAnsiString(buffer, value);
        WriteByte(buffer[value.Length..], 0x00);
    }

    public static void WriteNullTerminatedAnsiString(ref Span<byte> buffer, string value)
    {
        WriteNullTerminatedAnsiString(buffer, value);
        buffer = buffer[(value.Length + 1)..];
    }

    public static void WriteNullTerminatedUTF16String(Span<byte> buffer, string value)
    {
        WriteUTF16String(buffer, value);
        WriteBytes(buffer.Slice(value.Length * 2), [0x00, 0x00]);
    }

    public static void WriteNullTerminatedUTF16String(ref Span<byte> buffer, string value)
    {
        WriteNullTerminatedUTF16String(buffer, value);
        buffer = buffer[(value.Length * 2 + 2)..];
    }

    public static void WriteUTF8String(Stream stream, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        stream.Write(bytes, 0, bytes.Length);
    }

    public static void WriteUTF16BEString(Stream stream, string value)
    {
        var bytes = Encoding.BigEndianUnicode.GetBytes(value);
        stream.Write(bytes, 0, bytes.Length);
    }
}