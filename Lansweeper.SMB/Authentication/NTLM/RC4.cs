namespace Lansweeper.Smb.Authentication.NTLM;

public static class RC4
{
    public static byte[] Encrypt(byte[] key, byte[] data)
    {
        return EncryptOutput(key, data);
    }

    public static byte[] Decrypt(byte[] key, byte[] data)
    {
        return EncryptOutput(key, data);
    }

    private static byte[] EncryptInitialize(byte[] key)
    {
        var s = new byte[256];
        for (var index = 0; index < 256; index++) s[index] = (byte)index;

        for (int i = 0, j = 0; i < 256; i++)
        {
            j = (j + key[i % key.Length] + s[i]) & 255;

            Swap(s, i, j);
        }

        return s;
    }

    private static byte[] EncryptOutput(byte[] key, byte[] data)
    {
        var s = EncryptInitialize(key);

        var i = 0;
        var j = 0;

        var output = new byte[data.Length];
        for (var index = 0; index < data.Length; index++)
        {
            i = (i + 1) & 255;
            j = (j + s[i]) & 255;

            Swap(s, i, j);
            output[index] = (byte)(data[index] ^ s[(s[i] + s[j]) & 255]);
        }

        return output;
    }

    private static void Swap(byte[] s, int i, int j)
    {
        var c = s[i];

        s[i] = s[j];
        s[j] = c;
    }
}