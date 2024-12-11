namespace Lansweeper.Smb.Utilities;

public static class ByteUtils
{
    public static byte[] Concatenate(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Array.Copy(a, 0, result, 0, a.Length);
        Array.Copy(b, 0, result, a.Length, b.Length);
        return result;
    }

    public static bool AreByteArraysEqual(byte[] array1, byte[] array2)
    {
        if (array1.Length != array2.Length) return false;

        for (var index = 0; index < array1.Length; index++)
            if (array1[index] != array2[index])
                return false;

        return true;
    }

    /// <exception cref="ArgumentException"/>
    public static byte[] XOR(byte[] array1, byte[] array2)
    {
        if (array1.Length == array2.Length)
            return XOR(array1, 0, array2, 0, array1.Length);
        throw new ArgumentException("Arrays must be of equal length");
    }

    /// <exception cref="ArgumentOutOfRangeException"/>
    public static byte[] XOR(byte[] array1, int offset1, byte[] array2, int offset2, int length)
    {
#pragma warning disable S3928 // Parameter names used into ArgumentException constructors should match an existing one 
        if (offset1 + length > array1.Length || offset2 + length > array2.Length) throw new ArgumentOutOfRangeException();
#pragma warning restore S3928 // Parameter names used into ArgumentException constructors should match an existing one 

        var result = new byte[length];
        for (var index = 0; index < length; index++)
            result[index] = (byte)(array1[offset1 + index] ^ array2[offset2 + index]);
        return result;
    }

    public static long CopyStream(Stream input, Stream output)
    {
        // input may not support seeking, so don't use input.Position
        return CopyStream(input, output, long.MaxValue);
    }

    public static long CopyStream(Stream input, Stream output, long count)
    {
        const int MaxBufferSize = 1048576; // 1 MB
        var bufferSize = (int)Math.Min(MaxBufferSize, count);
        var buffer = new byte[bufferSize];
        long totalBytesRead = 0;
        while (totalBytesRead < count)
        {
            var numberOfBytesToRead = (int)Math.Min(bufferSize, count - totalBytesRead);
            var bytesRead = input.Read(buffer, 0, numberOfBytesToRead);
            totalBytesRead += bytesRead;
            output.Write(buffer, 0, bytesRead);
            if (bytesRead == 0) // no more bytes to read from input stream
                return totalBytesRead;
        }

        return totalBytesRead;
    }
}