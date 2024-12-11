using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Lansweeper.Smb.Utilities;

/// <summary>
///     Implements the Counter with CBC-MAC (CCM) detailed in RFC 3610
/// </summary>
public static class AesCcm
{
    private static byte[] CalculateMac(byte[] key, byte[] nonce, byte[] data, byte[] associatedData,
        int signatureLength)
    {
        var messageToAuthenticate = BuildB0Block(nonce, true, signatureLength, data.Length);
        if (associatedData.Length > 0)
        {
            if (associatedData.Length >= 65280)
                throw new NotSupportedException("Associated data length of 65280 or more is not supported");

            Span<byte> associatedDataLength = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(associatedDataLength, (ushort)associatedData.Length);
            messageToAuthenticate = [.. messageToAuthenticate, .. associatedDataLength, .. associatedData];
            var associatedDataPaddingLength = (16 - messageToAuthenticate.Length % 16) % 16;
            messageToAuthenticate = ByteUtils.Concatenate(messageToAuthenticate, new byte[associatedDataPaddingLength]);
        }

        messageToAuthenticate = ByteUtils.Concatenate(messageToAuthenticate, data);

        var dataPaddingLength = (16 - messageToAuthenticate.Length % 16) % 16;
        messageToAuthenticate = ByteUtils.Concatenate(messageToAuthenticate, new byte[dataPaddingLength]);

        var encrypted = AesEncrypt(key, new byte[16], messageToAuthenticate, CipherMode.CBC);

        return ByteReader.ReadBytes(encrypted.AsSpan(messageToAuthenticate.Length - 16), signatureLength);
    }

    public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, int signatureLength,
        out byte[] signature)
    {
        if (nonce.Length < 7 || nonce.Length > 13)
            throw new ArgumentException("nonce length must be between 7 and 13 bytes");

        if (signatureLength < 4 || signatureLength > 16 || signatureLength % 2 == 1)
            throw new ArgumentException("signature length must be an even number between 4 and 16 bytes");

        var keyStream = BuildKeyStream(key, nonce, data.Length);

        var mac = CalculateMac(key, nonce, data, associatedData, signatureLength);
        signature = ByteUtils.XOR(keyStream, 0, mac, 0, mac.Length);
        return ByteUtils.XOR(data, 0, keyStream, 16, data.Length);
    }

    public static byte[] DecryptAndAuthenticate(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData,
        byte[] signature)
    {
        if (nonce.Length < 7 || nonce.Length > 13)
            throw new ArgumentException("nonce length must be between 7 and 13 bytes");

        if (signature.Length < 4 || signature.Length > 16 || signature.Length % 2 == 1)
            throw new ArgumentException("signature length must be an even number between 4 and 16 bytes");

        var keyStream = BuildKeyStream(key, nonce, encryptedData.Length);

        var data = ByteUtils.XOR(encryptedData, 0, keyStream, 16, encryptedData.Length);

        var mac = CalculateMac(key, nonce, data, associatedData, signature.Length);
        var expectedSignature = ByteUtils.XOR(keyStream, 0, mac, 0, mac.Length);
        if (!ByteUtils.AreByteArraysEqual(expectedSignature, signature))
            throw new CryptographicException("The computed authentication value did not match the input");
        return data;
    }

    private static byte[] BuildKeyStream(byte[] key, byte[] nonce, int dataLength)
    {
        var paddingLength = 16 - dataLength % 16 % 16;
        var keyStreamLength = 16 + dataLength + paddingLength;
        var KeyStreamBlockCount = keyStreamLength / 16;
        var keyStreamInput = new byte[keyStreamLength];

        var keyStreamInputSpan = keyStreamInput.AsSpan();
        for (var index = 0; index < KeyStreamBlockCount; index++)
        {
            var aBlock = BuildABlock(nonce, index);
            ByteWriter.WriteBytes(ref keyStreamInputSpan, aBlock);
        }

        return AesEncrypt(key, new byte[16], keyStreamInput, CipherMode.ECB);
    }

    private static byte[] BuildB0Block(byte[] nonce, bool hasAssociatedData, int signatureLength, int messageLength)
    {
        var b0 = new byte[16];
        Array.Copy(nonce, 0, b0, 1, nonce.Length);
        var lengthFieldLength = 15 - nonce.Length;
        b0[0] = ComputeFlagsByte(hasAssociatedData, signatureLength, lengthFieldLength);

        var temp = messageLength;
        for (var index = 15; index > 15 - lengthFieldLength; index--)
        {
            b0[index] = (byte)(temp % 256);
            temp /= 256;
        }

        return b0;
    }

    private static byte[] BuildABlock(byte[] nonce, int blockIndex)
    {
        var aBlock = new byte[16];
        Array.Copy(nonce, 0, aBlock, 1, nonce.Length);
        var lengthFieldLength = 15 - nonce.Length;
        aBlock[0] = (byte)(lengthFieldLength - 1);

        var temp = blockIndex;
        for (var index = 15; index > 15 - lengthFieldLength; index--)
        {
            aBlock[index] = (byte)(temp % 256);
            temp /= 256;
        }

        return aBlock;
    }

    private static byte ComputeFlagsByte(bool hasAssociatedData, int signatureLength, int lengthFieldLength)
    {
        byte flags = 0;
        if (hasAssociatedData) flags |= 0x40;

        flags |= (byte)(lengthFieldLength - 1); // L'
        flags |= (byte)(((signatureLength - 2) / 2) << 3); // M'

        return flags;
    }

    private static byte[] AesEncrypt(byte[] key, byte[] iv, byte[] data, CipherMode cipherMode)
    {
        using var ms = new MemoryStream();
        using var aes = Aes.Create();
        aes.Mode = cipherMode;
        aes.Padding = PaddingMode.None;

        using var cs = new CryptoStream(ms, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();

        return ms.ToArray();
    }
}