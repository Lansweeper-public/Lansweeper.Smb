﻿using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.SMB2;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.SMB.Tests.SMB2;

// https://docs.microsoft.com/en-us/archive/blogs/openspecification/encryption-in-smb-3-0-a-protocol-perspective
internal class Smb2CryptographyShould
{
    [Test]
    public void TestEncryptionKeyGeneration()
    {
        byte[] sessionKey = [0xB4, 0x54, 0x67, 0x71, 0xB5, 0x15, 0xF7, 0x66, 0xA8, 0x67, 0x35, 0x53, 0x2D, 0xD6, 0xC4, 0xF0];
        byte[] expectedEncryptionKey = [0x26, 0x1B, 0x72, 0x35, 0x05, 0x58, 0xF2, 0xE9, 0xDC, 0xF6, 0x13, 0x07, 0x03, 0x83, 0xED, 0xBF];

        byte[] encryptionKey = Smb2Cryptography.GenerateClientEncryptionKey(sessionKey, Smb2Dialect.SMB300, null);

        encryptionKey.Should().Equal(expectedEncryptionKey);
    }

    [Test]
    public void TestDecryptionKeyGeneration()
    {
        byte[] sessionKey = [0xB4, 0x54, 0x67, 0x71, 0xB5, 0x15, 0xF7, 0x66, 0xA8, 0x67, 0x35, 0x53, 0x2D, 0xD6, 0xC4, 0xF0];
        byte[] decryptionKey = Smb2Cryptography.GenerateClientDecryptionKey(sessionKey, Smb2Dialect.SMB300, null);

        byte[] expectedDecryptionKey = [0x8F, 0xE2, 0xB5, 0x7E, 0xC3, 0x4D, 0x2D, 0xB5, 0xB1, 0xA9, 0x72, 0x7F, 0x52, 0x6B, 0xBD, 0xB5];

        decryptionKey.Should().Equal(expectedDecryptionKey);
    }

    [Test]
    public void TestEncryption()
    {
        byte[] encryptionKey = [0x26, 0x1B, 0x72, 0x35, 0x05, 0x58, 0xF2, 0xE9, 0xDC, 0xF6, 0x13, 0x07, 0x03, 0x83, 0xED, 0xBF];
        byte[] nonce = [0x66, 0xE6, 0x9A, 0x11, 0x18, 0x92, 0x58, 0x4F, 0xB5, 0xED, 0x52];
        ulong sessionID = 0x8e40014000011;

        byte[] message = [ 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x40, 0x00,
                            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0xFF, 0xFE, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x14, 0x00, 0xE4, 0x08, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x31, 0x00, 0x70, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x15, 0x01, 0x00, 0x00, 0x39, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x39, 0x02, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x53, 0x6D, 0x62, 0x33, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x20,
                            0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67];

        byte[] expectedEncrypted = [ 0x25, 0xC8, 0xFE, 0xE1, 0x66, 0x05, 0xA4, 0x37, 0x83, 0x2D, 0x1C, 0xD5, 0x2D, 0xA9, 0xF4, 0x64,
                                    0x53, 0x33, 0x48, 0x2A, 0x17, 0x5F, 0xE5, 0x38, 0x45, 0x63, 0xF4, 0x5F, 0xCD, 0xAF, 0xAE, 0xF3,
                                    0x8B, 0xC6, 0x2B, 0xA4, 0xD5, 0xC6, 0x28, 0x97, 0x99, 0x66, 0x25, 0xA4, 0x4C, 0x29, 0xBE, 0x56,
                                    0x58, 0xDE, 0x2E, 0x61, 0x17, 0x58, 0x57, 0x79, 0xE7, 0xB5, 0x9F, 0xFD, 0x97, 0x12, 0x78, 0xD0,
                                    0x85, 0x80, 0xD7, 0xFA, 0x89, 0x9E, 0x41, 0x0E, 0x91, 0x0E, 0xAB, 0xF5, 0xAA, 0x1D, 0xB4, 0x30,
                                    0x50, 0xB3, 0x3B, 0x49, 0x18, 0x26, 0x37, 0x75, 0x9A, 0xC1, 0x5D, 0x84, 0xBF, 0xCD, 0xF5, 0xB6,
                                    0xB2, 0x38, 0x99, 0x3C, 0x0F, 0x4C, 0xF4, 0xD6, 0x01, 0x20, 0x23, 0xF6, 0xC6, 0x27, 0x29, 0x70,
                                    0x75, 0xD8, 0x4B, 0x78, 0x03, 0x91, 0x2D, 0x0A, 0x96, 0x39, 0x63, 0x44, 0x53, 0x59, 0x5E, 0xF3,
                                    0xE3, 0x3F, 0xFE, 0x4E, 0x7A, 0xC2, 0xAB ];

        //byte[] expectedSignature = [0x81, 0xA2, 0x86, 0x53, 0x54, 0x15, 0x44, 0x5D, 0xAE, 0x39, 0x39, 0x21, 0xE4, 0x4F, 0xA4, 0x2E]

        byte[] signature;
        byte[] encryptedMessage = Smb2Cryptography.EncryptMessage(encryptionKey, nonce, message, sessionID, out signature);

        encryptedMessage.Should().Equal(expectedEncrypted);
        // The associated data in this sample include non-zero nonce padding so we ignore signature validation
    }

    [Test]
    public void TestDecryption()
    {
        byte[] decryptionKey = [0x8F, 0xE2, 0xB5, 0x7E, 0xC3, 0x4D, 0x2D, 0xB5, 0xB1, 0xA9, 0x72, 0x7F, 0x52, 0x6B, 0xBD, 0xB5];

        byte[] transformedPacket = [ 0xFD, 0x53, 0x4D, 0x42, 0xA6, 0x01, 0x55, 0x30, 0xA1, 0x8F, 0x6D, 0x9A, 0xFF, 0xE2, 0x2A, 0xFA,
                                                    0xE8, 0xE6, 0x64, 0x84, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x14,
                                                    0x00, 0xE4, 0x08, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x14,
                                                    0x00, 0xE4, 0x08, 0x00, 0xDB, 0xF4, 0x64, 0x35, 0xC5, 0xF1, 0x41, 0x69, 0x29, 0x3C, 0xE0, 0x79,
                                                    0xE3, 0x44, 0x47, 0x9B, 0xF6, 0x70, 0x22, 0x7E, 0x49, 0x87, 0x3F, 0x45, 0x86, 0x72, 0xC3, 0x09,
                                                    0x8D, 0xAC, 0x46, 0x7D, 0xD5, 0x80, 0x9F, 0x36, 0x9D, 0x67, 0x40, 0x91, 0x66, 0x51, 0x57, 0x87,
                                                    0x14, 0x83, 0xE0, 0x1F, 0x7B, 0xEC, 0xD0, 0x20, 0x64, 0xEA, 0xC3, 0xE2, 0x35, 0xF9, 0x13, 0x66,
                                                    0x8B, 0xBC, 0x2F, 0x09, 0x79, 0x80, 0xD4, 0xB3, 0x78, 0xF1, 0x99, 0x3E, 0xFF, 0x6E, 0x60, 0xD1,
                                                    0x77, 0x30, 0x9E, 0x5B ];

        byte[] expectedDecryptedMessage = [ 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x21, 0x00,
                                                           0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                           0xFF, 0xFE, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x14, 0x00, 0xE4, 0x08, 0x00,
                                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                           0x11, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ];

        Smb2TransformHeader transformHeader = new(transformedPacket);
        byte[] encryptedMessage = ByteReader.ReadBytes(transformedPacket.AsSpan(Smb2TransformHeader.Length), (int)transformHeader.OriginalMessageSize);
        byte[] decryptedMessage = Smb2Cryptography.DecryptMessage(decryptionKey, transformHeader, encryptedMessage);

        decryptedMessage.Should().Equal(expectedDecryptedMessage);
    }

    [Test]
    public void TestSMB202SignatureCalculation()
    {
        byte[] exportedSessionKey = [0xD3, 0x83, 0x54, 0xCC, 0x37, 0x43, 0x39, 0xF0, 0x52, 0x4F, 0x78, 0x91, 0x46, 0x78, 0x99, 0x21];

        byte[] message = [0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00, 0x28, 0x01, 0x00, 0xc0, 0x0b, 0x00, 0x07, 0x00,
                            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0xff, 0xfe, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                            0xfb, 0xd2, 0x84, 0x34, 0x03, 0x24, 0xc6, 0x2f, 0xbe, 0xbb, 0x65, 0xdd, 0x10, 0x51, 0xf3, 0xae,
                            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

        byte[] expectedSignature = [0xfb, 0xd2, 0x84, 0x34, 0x03, 0x24, 0xc6, 0x2f, 0xbe, 0xbb, 0x65, 0xdd, 0x10, 0x51, 0xf3, 0xae];

        message.AsSpan(48, 16).Clear();

        byte[] signature = Smb2Cryptography.CalculateSignature(exportedSessionKey, Smb2Dialect.SMB202, message, 0, message.Length);
        signature = ByteReader.ReadBytes(signature, 16);

        signature.Should().Equal(expectedSignature);
    }

    [Test]
    public void TestSMB210SignatureCalculation()
    {
        byte[] exportedSessionKey = [0x04, 0xE7, 0x07, 0x57, 0x1F, 0x8E, 0x03, 0x53, 0xB7, 0x7A, 0x94, 0xC3, 0x65, 0x3B, 0x87, 0xB5];

        byte[] message = [ 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00, 0x28, 0x01, 0x00, 0xc0, 0x0b, 0x00, 0x07, 0x00,
                            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0xff, 0xfe, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                            0xa1, 0x64, 0xff, 0xe5, 0x3d, 0x68, 0x11, 0x98, 0x1f, 0x38, 0x67, 0x72, 0xe3, 0x87, 0xe0, 0x6f,
                            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

        byte[] expectedSignature = [0xa1, 0x64, 0xff, 0xe5, 0x3d, 0x68, 0x11, 0x98, 0x1f, 0x38, 0x67, 0x72, 0xe3, 0x87, 0xe0, 0x6f];

        message.AsSpan(48, 16).Clear();

        byte[] signature = Smb2Cryptography.CalculateSignature(exportedSessionKey, Smb2Dialect.SMB210, message, 0, message.Length);
        signature = ByteReader.ReadBytes(signature, 16);

        signature.Should().Equal(expectedSignature);
    }

    [Test]
    public void TestSMB300SignatureCalculation()
    {
        byte[] exportedSessionKey = [0x35, 0x40, 0x24, 0xCB, 0xCA, 0x4F, 0x94, 0xAA, 0x51, 0xD4, 0x03, 0x3E, 0x6E, 0x9B, 0x2F, 0x98];
        byte[] signingKey = Smb2Cryptography.GenerateSigningKey(exportedSessionKey, Smb2Dialect.SMB300, null!);

        byte[] message = [ 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                                         0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x00, 0x20, 0x00, 0x70, 0x00, 0x00,
                                         0x73, 0xF2, 0xCC, 0x56, 0x09, 0x3E, 0xD2, 0xB5, 0xD7, 0x10, 0x66, 0x6C, 0xE4, 0x28, 0x2D, 0xD1,
                                         0x09, 0x00, 0x00, 0x00, 0x48, 0x00, 0x09, 0x00, 0xA1, 0x07, 0x30, 0x05, 0xA0, 0x03, 0x0A, 0x01, 0x00];

        byte[] expectedSignature = [0x73, 0xF2, 0xCC, 0x56, 0x09, 0x3E, 0xD2, 0xB5, 0xD7, 0x10, 0x66, 0x6C, 0xE4, 0x28, 0x2D, 0xD1];

        message.AsSpan(48, 16).Clear();

        byte[] signature = Smb2Cryptography.CalculateSignature(signingKey, Smb2Dialect.SMB300, message, 0, message.Length);
        signature = ByteReader.ReadBytes(signature, 16);

        signature.Should().Equal(expectedSignature);
    }
}
