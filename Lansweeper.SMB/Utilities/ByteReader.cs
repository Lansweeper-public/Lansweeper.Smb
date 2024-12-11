using System.Text;

namespace Lansweeper.Smb.Utilities;

public static class ByteReader
{
    /// <summary>
    /// Reads a byte from the buffer and advances the buffer
    /// </summary>
    public static byte ReadByte(ref ReadOnlySpan<byte> buffer)
    {
        byte result = buffer[0];
        buffer = buffer.Slice(1);
        return result;
    }

    public static byte[] ReadBytes(ReadOnlySpan<byte> buffer, int length)
    {
        return buffer[..length].ToArray();
    }

    /// <summary>
    /// Reads a number of bytes from the buffer and advances the buffer
    /// </summary>
    public static byte[] ReadBytes(ref ReadOnlySpan<byte> buffer, int length)
    {
        var result = buffer[..length].ToArray();
        buffer = buffer[length..];
        return result;
    }

    public static byte[] ReadBytes(Stream stream, int count)
    {
        using var temp = new MemoryStream();
        ByteUtils.CopyStream(stream, temp, count);
        return temp.ToArray();
    }

    /// <summary>
    ///     Will return the ANSI string stored in the buffer
    /// </summary>
    public static string ReadAnsiString(ReadOnlySpan<byte> buffer, int count)
    {
        // ASCIIEncoding.ASCII.GetString will convert some values to '?' (byte value of 63)
        // Any codepage will do, but the only one that Mono supports is 28591.
        return Encoding.GetEncoding(28591).GetString(buffer[..count]);
    }

    /// <summary>
    ///     Will return the ANSI string stored in the buffer
    /// </summary>
    public static string ReadAnsiString(ReadOnlySpan<byte> buffer)
    {
        // ASCIIEncoding.ASCII.GetString will convert some values to '?' (byte value of 63)
        // Any codepage will do, but the only one that Mono supports is 28591.
        return Encoding.GetEncoding(28591).GetString(buffer);
    }

    /// <summary>
    /// Reads a number of bytes from the buffer as ANSI characters and advances the buffer
    /// </summary>
    public static string ReadAnsiString(ref ReadOnlySpan<byte> buffer, int count)
    {
        var result = ReadAnsiString(buffer, count);
        buffer = buffer[count..];
        return result;
    }

    public static string ReadAnsiString(Stream stream, int length)
    {
        var buffer = ReadBytes(stream, length);
        return Encoding.GetEncoding(28591).GetString(buffer);
    }

    public static string ReadUTF16String(ReadOnlySpan<byte> buffer)
    {
        return Encoding.Unicode.GetString(buffer);
    }

    public static string ReadUTF16String(ReadOnlySpan<byte> buffer, int numberOfCharacters)
    {
        var numberOfBytes = numberOfCharacters * 2;
        return Encoding.Unicode.GetString(buffer[numberOfBytes..]);
    }

    public static string ReadUTF16String(ref ReadOnlySpan<byte> buffer, int numberOfCharacters)
    {
        var numberOfBytes = numberOfCharacters * 2;
        var result = ReadUTF16String(buffer, numberOfCharacters);
        buffer = buffer[numberOfBytes..];
        return result;
    }

    public static string ReadNullTerminatedAnsiString(ReadOnlySpan<byte> buffer)
    {
        const byte nullTerminatingByte = 0;
        int terminatingByteIndex = buffer.IndexOf(nullTerminatingByte);

        var result = Encoding.GetEncoding(28591).GetString(buffer[..terminatingByteIndex]);
        return result;
    }

    public static string ReadNullTerminatedAnsiString(ref ReadOnlySpan<byte> buffer)
    {
        var result = ReadNullTerminatedAnsiString(buffer);
        buffer = buffer[(result.Length + 1)..];
        return result;
    }

    public static string ReadNullTerminatedAnsiString(Stream stream)
    {
        var builder = new StringBuilder();
        var c = (char)stream.ReadByte();
        while (c != '\0')
        {
            builder.Append(c);
            c = (char)stream.ReadByte();
        }

        return builder.ToString();
    }

    public static string ReadNullTerminatedUTF16String(ReadOnlySpan<byte> buffer)
    {
        ReadOnlySpan<byte> nullTerminatingByte = [0, 0];
        int terminatingByteIndex = -1;

        for (int i = 0; i + 1 < buffer.Length; i += 2)
        {
            if (buffer.Slice(i, 2).SequenceEqual(nullTerminatingByte))
            {
                terminatingByteIndex = i;
                break;
            }
        }

        var result = Encoding.Unicode.GetString(buffer[..terminatingByteIndex]);
        return result;
    }

    public static string ReadNullTerminatedUTF16String(ref ReadOnlySpan<byte> buffer)
    {
        var result = ReadNullTerminatedUTF16String(buffer);
        buffer = buffer[(result.Length * 2 + 2)..];
        return result;
    }

    /// <summary>
    ///     Return all bytes from current stream position to the end of the stream
    /// </summary>
    public static byte[] ReadAllBytes(Stream stream)
    {
        using var temp = new MemoryStream();
        ByteUtils.CopyStream(stream, temp);
        return temp.ToArray();
    }

}