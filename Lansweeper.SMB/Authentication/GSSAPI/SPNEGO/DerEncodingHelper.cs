using System.Text;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;

public static class DerEncodingHelper
{
    public static int ReadLength(ref ReadOnlySpan<byte> buffer)
    {
        int length = ByteReader.ReadByte(ref buffer);
        if (length >= 0x80)
        {
            var lengthFieldSize = length & 0x7F;
            var lengthField = ByteReader.ReadBytes(ref buffer, lengthFieldSize);
            length = 0;
            foreach (var value in lengthField)
            {
                length *= 256;
                length += value;
            }
        }

        return length;
    }

    public static void WriteLength(ref Span<byte> buffer, int length)
    {
        if (length >= 0x80)
        {
            var values = new List<byte>();
            do
            {
                var value = (byte)(length % 256);
                values.Add(value);
                length = length / 256;
            } while (length > 0);

            values.Reverse();
            var lengthField = values.ToArray();
            ByteWriter.WriteByte(ref buffer, (byte)(0x80 | lengthField.Length));
            ByteWriter.WriteBytes(ref buffer, lengthField);
        }
        else
        {
            ByteWriter.WriteByte(ref buffer, (byte)length);
        }
    }

    public static int GetLengthFieldSize(int length)
    {
        if (length >= 0x80)
        {
            var result = 1;
            do
            {
                length = length / 256;
                result++;
            } while (length > 0);

            return result;
        }

        return 1;
    }

    public static byte[] EncodeGeneralString(string value)
    {
        // We do not support character-set designation escape sequences
        return Encoding.ASCII.GetBytes(value);
    }

    public static string DecodeGeneralString(byte[] bytes)
    {
        // We do not support character-set designation escape sequences
        return Encoding.ASCII.GetString(bytes);
    }
}