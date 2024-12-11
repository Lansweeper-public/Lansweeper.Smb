namespace Lansweeper.Smb.Utilities;

internal static class ByteArrayExtensions
{

    public static string ToMacString(this ReadOnlySpan<byte> byteArray)
    {
        if (byteArray.Length == 0) return string.Empty;

        return BytesToString(byteArray, ':');
    }

    /// <summary>
    /// Converts byte arrays to string.
    /// </summary>
    /// <param name="bytes">The bytes.</param>
    /// <param name="separator">Separator character between bytes</param>
    /// <returns>The resulting hexadecimal string (e.g. for an MD5 hash: 91673F229DB4A5C710E0EA365B3F0B7D)</returns>
    private static string BytesToString(ReadOnlySpan<byte> bytes, char? separator = null)
    {
        var index = 0;
        var index2 = 0;
        var dst = separator is null ? new char[bytes.Length * 2] : new char[bytes.Length * 3 - 1];
        while (index < bytes.Length)
        {
            if (index > 0 && separator.HasValue)
            {
                dst[index2++] = separator.Value;
            }
            var b = bytes[index++];
            dst[index2++] = ToCharUpper(b >> 4);
            dst[index2++] = ToCharUpper(b);
        }
        return new string(dst);
    }

    private static char ToCharUpper(int value)
    {
        value &= 0xF;
        value += 48;
        if (value > 57)
        {
            value += 7;
        }
        return (char)value;
    }
}