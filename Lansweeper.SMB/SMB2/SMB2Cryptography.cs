using System.Security.Cryptography;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;
using AesCcm = Lansweeper.Smb.Utilities.AesCcm;
using HashAlgorithm = Lansweeper.Smb.SMB2.Enums.HashAlgorithm;

namespace Lansweeper.Smb.SMB2;

public static class Smb2Cryptography // TODO make internal
{
    private const int AesCcmNonceLength = 11;

    public static byte[] CalculateSignature(byte[] signingKey, Smb2Dialect dialect, byte[] buffer, int offset,
        int paddedLength)
    {
        if (dialect == Smb2Dialect.SMB202 || dialect == Smb2Dialect.SMB210)
            return new HMACSHA256(signingKey).ComputeHash(buffer, offset, paddedLength);
        return AesCmac.CalculateAesCmac(signingKey, buffer, offset, paddedLength);
    }

    public static byte[] GenerateSigningKey(byte[] sessionKey, Smb2Dialect dialect, byte[] preauthIntegrityHashValue)
    {
        if (dialect == Smb2Dialect.SMB202 || dialect == Smb2Dialect.SMB210) return sessionKey;

        if (dialect == Smb2Dialect.SMB311 && preauthIntegrityHashValue == null)
            throw new ArgumentNullException(nameof(preauthIntegrityHashValue));

        var labelString = dialect == Smb2Dialect.SMB311 ? "SMBSigningKey" : "SMB2AESCMAC";
        var label = GetNullTerminatedAnsiString(labelString);
        var context = dialect == Smb2Dialect.SMB311
            ? preauthIntegrityHashValue
            : GetNullTerminatedAnsiString("SmbSign");

        var hmac = new HMACSHA256(sessionKey);
        return SP800_1008.DeriveKey(hmac, label, context, 128);
    }

    public static byte[] GenerateClientEncryptionKey(byte[] sessionKey, Smb2Dialect dialect, byte[]? preauthIntegrityHashValue)
    {
        if (dialect == Smb2Dialect.SMB311 && preauthIntegrityHashValue is null)
            throw new ArgumentNullException(nameof(preauthIntegrityHashValue));

        var labelString = dialect == Smb2Dialect.SMB311 ? "SMBC2SCipherKey" : "SMB2AESCCM";
        var label = GetNullTerminatedAnsiString(labelString);
        var context = dialect == Smb2Dialect.SMB311
            ? preauthIntegrityHashValue
            : GetNullTerminatedAnsiString("ServerIn ");

        var hmac = new HMACSHA256(sessionKey);
        return SP800_1008.DeriveKey(hmac, label, context, 128);
    }

    public static byte[] GenerateClientDecryptionKey(byte[] sessionKey, Smb2Dialect dialect, byte[]? preauthIntegrityHashValue)
    {
        if (dialect == Smb2Dialect.SMB311 && preauthIntegrityHashValue is null)
            throw new ArgumentNullException(nameof(preauthIntegrityHashValue));

        var labelString = dialect == Smb2Dialect.SMB311 ? "SMBS2CCipherKey" : "SMB2AESCCM";
        var label = GetNullTerminatedAnsiString(labelString);
        var context = dialect == Smb2Dialect.SMB311
            ? preauthIntegrityHashValue
            : GetNullTerminatedAnsiString("ServerOut");

        var hmac = new HMACSHA256(sessionKey);
        return SP800_1008.DeriveKey(hmac, label, context, 128);
    }

    /// <summary>
    ///     Encrypt message and prefix with SMB2 TransformHeader
    /// </summary>
    public static byte[] TransformMessage(byte[] key, byte[] message, ulong sessionID)
    {
        var nonce = GenerateAesCcmNonce();
        var encryptedMessage = EncryptMessage(key, nonce, message, sessionID, out byte[] signature);
        var transformHeader = CreateTransformHeader(nonce, message.Length, sessionID);
        transformHeader.Signature = signature;

        var buffer = new byte[Smb2TransformHeader.Length + message.Length];
        transformHeader.WriteBytes(buffer);

        ByteWriter.WriteBytes(buffer.AsSpan(Smb2TransformHeader.Length), encryptedMessage);

        return buffer;
    }

    public static byte[] EncryptMessage(byte[] key, byte[] nonce, byte[] message, ulong sessionID, out byte[] signature)
    {
        var transformHeader = CreateTransformHeader(nonce, message.Length, sessionID);
        var associatedata = transformHeader.GetAssociatedData();
        return AesCcm.Encrypt(key, nonce, message, associatedata, Smb2TransformHeader.SignatureLength, out signature);
    }

    public static byte[] DecryptMessage(byte[] key, Smb2TransformHeader transformHeader, byte[] encryptedMessage)
    {
        var associatedData = transformHeader.GetAssociatedData();
        var aesCcmNonce = ByteReader.ReadBytes(transformHeader.Nonce, AesCcmNonceLength);
        return AesCcm.DecryptAndAuthenticate(key, aesCcmNonce, encryptedMessage, associatedData,
            transformHeader.Signature);
    }

    public static byte[] ComputeHash(HashAlgorithm hashAlgorithm, byte[] buffer)
    {
        if (hashAlgorithm != HashAlgorithm.SHA512)
            throw new NotSupportedException($"Hash algorithm {hashAlgorithm} is not supported");
        return SHA512.HashData(buffer);
    }

    private static Smb2TransformHeader CreateTransformHeader(byte[] nonce, int originalMessageLength, ulong sessionID)
    {
        var nonceWithPadding = new byte[Smb2TransformHeader.NonceLength];
        Array.Copy(nonce, nonceWithPadding, nonce.Length);

        var transformHeader = new Smb2TransformHeader
        {
            Nonce = nonceWithPadding,
            OriginalMessageSize = (uint)originalMessageLength,
            Flags = Smb2TransformHeaderFlags.Encrypted,
            SessionId = sessionID
        };

        return transformHeader;
    }

    private static byte[] GenerateAesCcmNonce()
    {
        var aesCcmNonce = new byte[AesCcmNonceLength];
        Random.Shared.NextBytes(aesCcmNonce);
        return aesCcmNonce;
    }

    private static byte[] GetNullTerminatedAnsiString(string value)
    {
        var result = new byte[value.Length + 1];
        ByteWriter.WriteNullTerminatedAnsiString(result, value);
        return result;
    }

}