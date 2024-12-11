using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.NTLM;

public static class NtlmCryptography
{
    public static byte[] ComputeLMv1Response(byte[] challenge, string password)
    {
        var hash = LMOWFv1(password);
        return DesLongEncrypt(hash, challenge);
    }

    public static byte[] ComputeNTLMv1Response(byte[] challenge, string password)
    {
        var hash = NTOWFv1(password);
        return DesLongEncrypt(hash, challenge);
    }

    public static byte[] ComputeNTLMv1ExtendedSessionSecurityResponse(byte[] serverChallenge, byte[] clientChallenge,
        string password)
    {
        var passwordHash = NTOWFv1(password);
        var challengeHash = MD5.HashData(ByteUtils.Concatenate(serverChallenge, clientChallenge));
        var challengeHashShort = new byte[8];
        Array.Copy(challengeHash, 0, challengeHashShort, 0, 8);
        return DesLongEncrypt(passwordHash, challengeHashShort);
    }

    public static byte[] ComputeLMv2Response(byte[] serverChallenge, byte[] clientChallenge, string password,
        string user, string domain)
    {
        var key = LMOWFv2(password, user, domain);
        var bytes = ByteUtils.Concatenate(serverChallenge, clientChallenge);
        var hash = HMACMD5.HashData(key, bytes);

        return ByteUtils.Concatenate(hash, clientChallenge);
    }

    /// <summary>
    ///     [MS-NLMP] https://msdn.microsoft.com/en-us/library/cc236700.aspx
    /// </summary>
    /// <param name="clientChallengeStructurePadded">ClientChallengeStructure with 4 zero bytes padding, a.k.a. temp</param>
    public static byte[] ComputeNTLMv2Proof(byte[] serverChallenge, byte[] clientChallengeStructurePadded,
        string password, string user, string domain)
    {
        var key = NTOWFv2(password, user, domain);
        var temp = clientChallengeStructurePadded;

        var _NTProof = HMACMD5.HashData(key, ByteUtils.Concatenate(serverChallenge, temp));

        return _NTProof;
    }

    public static byte[] DesEncrypt(byte[] key, byte[] plainText)
    {
        return DesEncrypt(key, plainText, 0, plainText.Length);
    }

    public static byte[] DesEncrypt(byte[] key, byte[] plainText, int inputOffset, int inputCount)
    {
        var encryptor = CreateWeakDesEncryptor(CipherMode.ECB, key, new byte[key.Length]);
        var result = new byte[inputCount];
        encryptor.TransformBlock(plainText, inputOffset, inputCount, result, 0);
        return result;
    }

#pragma warning disable S5547 // Cipher algorithms should be robust
#pragma warning disable S3011 // Reflection should not be used to increase accessibility of classes, methods, or fields
    public static ICryptoTransform CreateWeakDesEncryptor(CipherMode mode, byte[] rgbKey, byte[] rgbIV)
    {
        using var des = DES.Create();
        des.Mode = mode;
        ICryptoTransform transform;
        if (DES.IsWeakKey(rgbKey) || DES.IsSemiWeakKey(rgbKey))
        {
            // TODO try to get rid of this reflection
            MethodInfo getTransformCoreMethodInfo = des.GetType().GetMethod("CreateTransformCore", BindingFlags.NonPublic | BindingFlags.Static)!;
            object[] getTransformCoreParameters = { mode, des.Padding, rgbKey, rgbIV, des.BlockSize / 8, des.FeedbackSize / 8, des.BlockSize / 8, true };
            transform = (getTransformCoreMethodInfo.Invoke(null, getTransformCoreParameters) as ICryptoTransform)!;
        }
        else
        {
            transform = des.CreateEncryptor(rgbKey, rgbIV);
        }

        return transform;
    }
#pragma warning restore S5547 // Cipher algorithms should be robust
#pragma warning restore S3011 // Reflection should not be used to increase accessibility of classes, methods, or fields

    /// <summary>
    ///     DESL()
    /// </summary>
    public static byte[] DesLongEncrypt(byte[] key, byte[] plainText)
    {
        if (key.Length != 16) throw new ArgumentException("Invalid key length");

        if (plainText.Length != 8) throw new ArgumentException("Invalid plain-text length");
        var padded = new byte[21];
        Array.Copy(key, padded, key.Length);

        var k1 = new byte[7];
        var k2 = new byte[7];
        var k3 = new byte[7];
        Array.Copy(padded, 0, k1, 0, 7);
        Array.Copy(padded, 7, k2, 0, 7);
        Array.Copy(padded, 14, k3, 0, 7);

        var r1 = DesEncrypt(ExtendDESKey(k1), plainText);
        var r2 = DesEncrypt(ExtendDESKey(k2), plainText);
        var r3 = DesEncrypt(ExtendDESKey(k3), plainText);

        var result = new byte[24];
        Array.Copy(r1, 0, result, 0, 8);
        Array.Copy(r2, 0, result, 8, 8);
        Array.Copy(r3, 0, result, 16, 8);

        return result;
    }

    public static Encoding GetOEMEncoding()
    {
        return Encoding.GetEncoding(28591);
    }

    /// <summary>
    ///     LM Hash
    /// </summary>
    public static byte[] LMOWFv1(string password)
    {
        var plainText = Encoding.ASCII.GetBytes("KGS!@#$%");
        var passwordBytes = GetOEMEncoding().GetBytes(password.ToUpper());
        var key = new byte[14];
        Array.Copy(passwordBytes, key, Math.Min(passwordBytes.Length, 14));

        var k1 = new byte[7];
        var k2 = new byte[7];
        Array.Copy(key, 0, k1, 0, 7);
        Array.Copy(key, 7, k2, 0, 7);

        var part1 = DesEncrypt(ExtendDESKey(k1), plainText);
        var part2 = DesEncrypt(ExtendDESKey(k2), plainText);

        return ByteUtils.Concatenate(part1, part2);
    }

    /// <summary>
    ///     NTLM hash (NT hash)
    /// </summary>
    public static byte[] NTOWFv1(string password)
    {
        var passwordBytes = Encoding.Unicode.GetBytes(password);
        return MD4.GetByteHashFromBytes(passwordBytes);
    }

    /// <summary>
    ///     LMOWFv2 is identical to NTOWFv2
    /// </summary>
    public static byte[] LMOWFv2(string password, string user, string domain)
    {
        return NTOWFv2(password, user, domain);
    }

    public static byte[] NTOWFv2(string password, string user, string domain)
    {
        var passwordBytes = Encoding.Unicode.GetBytes(password);
        var key = MD4.GetByteHashFromBytes(passwordBytes);
        var text = user.ToUpper() + domain;
        var bytes = Encoding.Unicode.GetBytes(text);
        return HMACMD5.HashData(key, bytes);
    }

    /// <summary>
    ///     Extends a 7-byte key into an 8-byte key.
    ///     Note: The DES key ostensibly consists of 64 bits, however, only 56 of these are actually used by the algorithm.
    ///     Eight bits are used solely for checking parity, and are thereafter discarded
    /// </summary>
    private static byte[] ExtendDESKey(byte[] key)
    {
        var result = new byte[8];
        int i;

        result[0] = (byte)((key[0] >> 1) & 0xff);
        result[1] = (byte)((((key[0] & 0x01) << 6) | (((key[1] & 0xff) >> 2) & 0xff)) & 0xff);
        result[2] = (byte)((((key[1] & 0x03) << 5) | (((key[2] & 0xff) >> 3) & 0xff)) & 0xff);
        result[3] = (byte)((((key[2] & 0x07) << 4) | (((key[3] & 0xff) >> 4) & 0xff)) & 0xff);
        result[4] = (byte)((((key[3] & 0x0F) << 3) | (((key[4] & 0xff) >> 5) & 0xff)) & 0xff);
        result[5] = (byte)((((key[4] & 0x1F) << 2) | (((key[5] & 0xff) >> 6) & 0xff)) & 0xff);
        result[6] = (byte)((((key[5] & 0x3F) << 1) | (((key[6] & 0xff) >> 7) & 0xff)) & 0xff);
        result[7] = (byte)(key[6] & 0x7F);
        for (i = 0; i < 8; i++) result[i] = (byte)(result[i] << 1);

        return result;
    }

    /// <summary>
    ///     [MS-NLMP] 3.4.5.1 - KXKEY - NTLM v1
    /// </summary>
    /// <remarks>
    ///     If NTLM v2 is used, KeyExchangeKey MUST be set to the value of SessionBaseKey.
    /// </remarks>
    public static byte[] KXKey(byte[] sessionBaseKey, NegotiateFlags negotiateFlags, byte[] lmChallengeResponse,
        byte[] serverChallenge, byte[] lmowf)
    {
        if ((negotiateFlags & NegotiateFlags.ExtendedSessionSecurity) == 0)
        {
            if ((negotiateFlags & NegotiateFlags.LanManagerSessionKey) > 0)
            {
                var k1 = ByteReader.ReadBytes(lmowf, 7);
                byte[] k2 = [..ByteReader.ReadBytes(lmowf.AsSpan(7), 1), 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD];
                var temp1 = DesEncrypt(ExtendDESKey(k1), ByteReader.ReadBytes(lmChallengeResponse, 8));
                var temp2 = DesEncrypt(ExtendDESKey(k2), ByteReader.ReadBytes(lmChallengeResponse, 8));
                var keyExchangeKey = ByteUtils.Concatenate(temp1, temp2);
                return keyExchangeKey;
            }

            if ((negotiateFlags & NegotiateFlags.RequestLMSessionKey) > 0)
            {
                var keyExchangeKey = ByteUtils.Concatenate(ByteReader.ReadBytes(lmowf, 8), new byte[8]);
                return keyExchangeKey;
            }

            return sessionBaseKey;
        }
        else
        {
            var buffer = ByteUtils.Concatenate(serverChallenge, ByteReader.ReadBytes(lmChallengeResponse, 8));
            var keyExchangeKey = HMACMD5.HashData(sessionBaseKey, buffer);
            return keyExchangeKey;
        }
    }

    /// <remarks>
    ///     Caller must verify that the authenticate message has MIC before calling this method
    /// </remarks>
    public static bool ValidateAuthenticateMessageMIC(byte[] exportedSessionKey, byte[] negotiateMessageBytes,
        byte[] challengeMessageBytes, byte[] authenticateMessageBytes)
    {
        // https://msdn.microsoft.com/en-us/library/cc236695.aspx
        var micFieldOffset = AuthenticateMessage.GetMicFieldOffset(authenticateMessageBytes);
        var expectedMic = ByteReader.ReadBytes(authenticateMessageBytes.AsSpan(micFieldOffset), AuthenticateMessage.MicFieldLength);

        ByteWriter.WriteBytes(authenticateMessageBytes.AsSpan(micFieldOffset), new byte[AuthenticateMessage.MicFieldLength]);
        var temp = ByteUtils.Concatenate(ByteUtils.Concatenate(negotiateMessageBytes, challengeMessageBytes),
            authenticateMessageBytes);
        var mic = HMACMD5.HashData(exportedSessionKey,temp);

        return ByteUtils.AreByteArraysEqual(mic, expectedMic);
    }

    public static byte[] ComputeClientSignKey(byte[] exportedSessionKey)
    {
        return ComputeSignKey(exportedSessionKey, true);
    }

    public static byte[] ComputeServerSignKey(byte[] exportedSessionKey)
    {
        return ComputeSignKey(exportedSessionKey, false);
    }

    private static byte[] ComputeSignKey(byte[] exportedSessionKey, bool isClient)
    {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/524cdccb-563e-4793-92b0-7bc321fce096
        string str;
        if (isClient)
            str = "session key to client-to-server signing key magic constant";
        else
            str = "session key to server-to-client signing key magic constant";
        var encodedString = Encoding.GetEncoding(28591).GetBytes(str);
        var nullTerminatedEncodedString = ByteUtils.Concatenate(encodedString, new byte[1]);
        var concatenated = ByteUtils.Concatenate(exportedSessionKey, nullTerminatedEncodedString);
        return MD5.HashData(concatenated);
    }

    public static byte[] ComputeClientSealKey(byte[] exportedSessionKey)
    {
        return ComputeSealKey(exportedSessionKey, true);
    }

    public static byte[] ComputeServerSealKey(byte[] exportedSessionKey)
    {
        return ComputeSealKey(exportedSessionKey, false);
    }

    private static byte[] ComputeSealKey(byte[] exportedSessionKey, bool isClient)
    {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/524cdccb-563e-4793-92b0-7bc321fce096
        string str;
        if (isClient)
            str = "session key to client-to-server sealing key magic constant";
        else
            str = "session key to server-to-client sealing key magic constant";
        var encodedString = Encoding.GetEncoding(28591).GetBytes(str);
        var nullTerminatedEncodedString = ByteUtils.Concatenate(encodedString, new byte[1]);
        var concatenated = ByteUtils.Concatenate(exportedSessionKey, nullTerminatedEncodedString);
        return MD5.HashData(concatenated);
    }

    public static byte[] ComputeMechListMIC(byte[] exportedSessionKey, byte[] message)
    {
        return ComputeMechListMIC(exportedSessionKey, message, 0);
    }

    public static byte[] ComputeMechListMIC(byte[] exportedSessionKey, byte[] message, int seqNum)
    {
        // [MS-NLMP] 3.4.4.2
        var signKey = ComputeClientSignKey(exportedSessionKey);

        Span<byte> sequenceNumberBytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(sequenceNumberBytes, seqNum);
        byte[] concatenated = [..sequenceNumberBytes, ..message];
        var fullHash = HMACMD5.HashData(signKey,concatenated);
        var hash = ByteReader.ReadBytes(fullHash, 8);

        var sealKey = ComputeClientSealKey(exportedSessionKey);
        var encryptedHash = RC4.Encrypt(sealKey, hash);

        return [0x01, 0x00, 0x00, 0x00 /*version*/, .. encryptedHash, .. sequenceNumberBytes];
    }
}