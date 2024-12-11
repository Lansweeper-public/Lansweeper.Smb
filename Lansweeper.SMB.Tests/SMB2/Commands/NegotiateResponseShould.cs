﻿using FluentAssertions.Extensions;
using Lansweeper.Smb.Enums;
using Lansweeper.Smb.SMB2.Commands;
using Lansweeper.Smb.SMB2.Commands.NegotiateContexts;
using Lansweeper.Smb.SMB2.Enums;

namespace Lansweeper.SMB.Tests.SMB2.Commands;

internal class NegotiateResponseShould
{
    static readonly byte[] EmptySignature = new byte[16];

    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        byte[] securityBlob = [
          0x60, 0x82, 0x01, 0x3c, 0x06, 0x06, 0x2b, 0x06,
          0x01, 0x05, 0x05, 0x02, 0xa0, 0x82, 0x01, 0x30,
          0x30, 0x82, 0x01, 0x2c, 0xa0, 0x1a, 0x30, 0x18,
          0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
          0x37, 0x02, 0x02, 0x1e, 0x06, 0x0a, 0x2b, 0x06,
          0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
          0xa2, 0x82, 0x01, 0x0c, 0x04, 0x82, 0x01, 0x08,
          0x4e, 0x45, 0x47, 0x4f, 0x45, 0x58, 0x54, 0x53,
          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x60, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00,
          0x82, 0xb2, 0x3b, 0xa7, 0xca, 0xcc, 0x4e, 0x21,
          0x63, 0x23, 0xca, 0x84, 0x72, 0x06, 0x1e, 0xfb,
          0xbf, 0xc8, 0x83, 0xb0, 0x6f, 0x9f, 0x4d, 0xf8,
          0x19, 0xd7, 0x61, 0x98, 0xde, 0x37, 0x91, 0xfe,
          0x38, 0xa8, 0x61, 0x3c, 0xdd, 0x28, 0x32, 0x87,
          0x9c, 0x8e, 0x5d, 0x11, 0x91, 0xff, 0x60, 0x17,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x5c, 0x33, 0x53, 0x0d, 0xea, 0xf9, 0x0d, 0x4d,
          0xb2, 0xec, 0x4a, 0xe3, 0x78, 0x6e, 0xc3, 0x08,
          0x4e, 0x45, 0x47, 0x4f, 0x45, 0x58, 0x54, 0x53,
          0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
          0x40, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00,
          0x82, 0xb2, 0x3b, 0xa7, 0xca, 0xcc, 0x4e, 0x21,
          0x63, 0x23, 0xca, 0x84, 0x72, 0x06, 0x1e, 0xfb,
          0x5c, 0x33, 0x53, 0x0d, 0xea, 0xf9, 0x0d, 0x4d,
          0xb2, 0xec, 0x4a, 0xe3, 0x78, 0x6e, 0xc3, 0x08,
          0x40, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
          0x30, 0x56, 0xa0, 0x54, 0x30, 0x52, 0x30, 0x27,
          0x80, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1f,
          0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54,
          0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x53, 0x69, 0x67,
          0x6e, 0x69, 0x6e, 0x67, 0x20, 0x50, 0x75, 0x62,
          0x6c, 0x69, 0x63, 0x20, 0x4b, 0x65, 0x79, 0x30,
          0x27, 0x80, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30,
          0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18,
          0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x53, 0x69,
          0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x50, 0x75,
          0x62, 0x6c, 0x69, 0x63, 0x20, 0x4b, 0x65, 0x79
        ];

        byte[] buffer = [
          0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x41, 0x00, 0x01, 0x00, 0x11, 0x03, 0x02, 0x00,
          0x96, 0x6e, 0xaf, 0xa3, 0x35, 0x7f, 0x04, 0x40,
          0xa5, 0xf9, 0x64, 0x3e, 0x1b, 0xfa, 0x8c, 0x56,
          0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
          0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
          0x0b, 0xd7, 0xd7, 0x87, 0x85, 0x27, 0xd2, 0x01,
          0xa1, 0xf3, 0xae, 0x87, 0x84, 0x27, 0xd2, 0x01,
          0x80, 0x00, 0x40, 0x01, 0xc0, 0x01, 0x00, 0x00,
          ..securityBlob,
          0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0xc2, 0x08,
          0xbe, 0xc6, 0xb2, 0xe6, 0x6b, 0x57, 0x96, 0x5e,
          0xf8, 0x92, 0x2e, 0xc8, 0xb9, 0xff, 0xeb, 0x99,
          0x25, 0xc0, 0x02, 0x54, 0xf2, 0x48, 0x93, 0x27,
          0xb6, 0x40, 0xb7, 0xb2, 0x0f, 0x91, 0x00, 0x00,
          0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x01, 0x00, 0x02, 0x00
        ];

        byte[] expectedSalt = [
          0xc2, 0x08, 0xbe, 0xc6, 0xb2, 0xe6, 0x6b, 0x57,
          0x96, 0x5e, 0xf8, 0x92, 0x2e, 0xc8, 0xb9, 0xff,
          0xeb, 0x99, 0x25, 0xc0, 0x02, 0x54, 0xf2, 0x48,
          0x93, 0x27, 0xb6, 0x40, 0xb7, 0xb2, 0x0f, 0x91
        ];

        NegotiateResponse sut = new(buffer);

        sut.Header.CreditCharge.Should().Be(0);
        sut.Header.Status.Should().Be(NTStatus.STATUS_SUCCESS);
        sut.Header.Command.Should().Be(Smb2CommandName.Negotiate);
        sut.Header.Credits.Should().Be(1);
        sut.Header.IsResponse.Should().BeTrue();
        sut.Header.IsAsync.Should().BeFalse();
        sut.Header.IsRelatedOperations.Should().BeFalse();
        sut.Header.IsSigned.Should().BeFalse();
        sut.Header.Priority.Should().Be(0);
        sut.Header.MessageID.Should().Be(1);
        sut.Header.Reserved.Should().Be(0xfeff);
        sut.Header.TreeID.Should().Be(0);
        sut.Header.SessionID.Should().Be(0);
        sut.Header.Signature.Should().Equal(EmptySignature);

        sut.SecurityMode.Should().Be(SecurityMode.SigningEnabled);
        sut.DialectRevision.Should().Be(Smb2Dialect.SMB311);
        sut.ServerGuid.Should().Be(new Guid("a3af6e96-7f35-4004-a5f9-643e1bfa8c56"));
        sut.Capabilities.Should().Be(Capabilities.DFS | Capabilities.Leasing | Capabilities.LargeMTU |
            Capabilities.MultiChannel | Capabilities.DirectoryLeasing);
        sut.MaxTransactSize.Should().Be(8388608);
        sut.MaxReadSize.Should().Be(8388608);
        sut.MaxWriteSize.Should().Be(8388608);
        sut.SystemTime.Should().Be(new DateTime(2016, 10, 16, 8, 16, 1, 36, 877, DateTimeKind.Utc).AddNanoseconds(900));
        sut.ServerStartTime.Should().Be(new DateTime(2016, 10, 16, 8, 8, 51,272,182, DateTimeKind.Utc).AddNanoseconds(500));
        sut.SecurityBuffer.Should().Equal(securityBlob);
        sut.NegotiateContextList.Should().HaveCount(2);

        var preAuth = sut.NegotiateContextList[0].Should().BeOfType<PreAuthIntegrityCapabilities>().Which;
        preAuth.DataLength.Should().Be(38);
        preAuth.Reserved.Should().Be(0);
        preAuth.HashAlgorithms.Should().Equal(HashAlgorithm.SHA512);
        preAuth.Salt.Should().Equal(expectedSalt);

        var encryption = sut.NegotiateContextList[1].Should().BeOfType<EncryptionCapabilities>().Which;
        encryption.DataLength.Should().Be(4);
        encryption.Reserved.Should().Be(0);
        encryption.Ciphers.Should().Equal(CipherAlgorithm.Aes128Gcm);
    }


    [Test]
    public void GetBytesCorrectly()
    {
        byte[] securityBlob = [
          0x60, 0x82, 0x01, 0x3c, 0x06, 0x06, 0x2b, 0x06,
          0x01, 0x05, 0x05, 0x02, 0xa0, 0x82, 0x01, 0x30,
          0x30, 0x82, 0x01, 0x2c, 0xa0, 0x1a, 0x30, 0x18,
          0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
          0x37, 0x02, 0x02, 0x1e, 0x06, 0x0a, 0x2b, 0x06,
          0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
          0xa2, 0x82, 0x01, 0x0c, 0x04, 0x82, 0x01, 0x08,
          0x4e, 0x45, 0x47, 0x4f, 0x45, 0x58, 0x54, 0x53,
          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x60, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00,
          0x82, 0xb2, 0x3b, 0xa7, 0xca, 0xcc, 0x4e, 0x21,
          0x63, 0x23, 0xca, 0x84, 0x72, 0x06, 0x1e, 0xfb,
          0xbf, 0xc8, 0x83, 0xb0, 0x6f, 0x9f, 0x4d, 0xf8,
          0x19, 0xd7, 0x61, 0x98, 0xde, 0x37, 0x91, 0xfe,
          0x38, 0xa8, 0x61, 0x3c, 0xdd, 0x28, 0x32, 0x87,
          0x9c, 0x8e, 0x5d, 0x11, 0x91, 0xff, 0x60, 0x17,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x5c, 0x33, 0x53, 0x0d, 0xea, 0xf9, 0x0d, 0x4d,
          0xb2, 0xec, 0x4a, 0xe3, 0x78, 0x6e, 0xc3, 0x08,
          0x4e, 0x45, 0x47, 0x4f, 0x45, 0x58, 0x54, 0x53,
          0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
          0x40, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00,
          0x82, 0xb2, 0x3b, 0xa7, 0xca, 0xcc, 0x4e, 0x21,
          0x63, 0x23, 0xca, 0x84, 0x72, 0x06, 0x1e, 0xfb,
          0x5c, 0x33, 0x53, 0x0d, 0xea, 0xf9, 0x0d, 0x4d,
          0xb2, 0xec, 0x4a, 0xe3, 0x78, 0x6e, 0xc3, 0x08,
          0x40, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
          0x30, 0x56, 0xa0, 0x54, 0x30, 0x52, 0x30, 0x27,
          0x80, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1f,
          0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54,
          0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x53, 0x69, 0x67,
          0x6e, 0x69, 0x6e, 0x67, 0x20, 0x50, 0x75, 0x62,
          0x6c, 0x69, 0x63, 0x20, 0x4b, 0x65, 0x79, 0x30,
          0x27, 0x80, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30,
          0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18,
          0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x53, 0x69,
          0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x50, 0x75,
          0x62, 0x6c, 0x69, 0x63, 0x20, 0x4b, 0x65, 0x79
        ];

        byte[] expectedBytes = [
          0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x41, 0x00, 0x01, 0x00, 0x11, 0x03, 0x02, 0x00,
          0x96, 0x6e, 0xaf, 0xa3, 0x35, 0x7f, 0x04, 0x40,
          0xa5, 0xf9, 0x64, 0x3e, 0x1b, 0xfa, 0x8c, 0x56,
          0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
          0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
          0x0b, 0xd7, 0xd7, 0x87, 0x85, 0x27, 0xd2, 0x01,
          0xa1, 0xf3, 0xae, 0x87, 0x84, 0x27, 0xd2, 0x01,
          0x80, 0x00, 0x40, 0x01, 0xc0, 0x01, 0x00, 0x00,
          ..securityBlob,
          0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0xc2, 0x08,
          0xbe, 0xc6, 0xb2, 0xe6, 0x6b, 0x57, 0x96, 0x5e,
          0xf8, 0x92, 0x2e, 0xc8, 0xb9, 0xff, 0xeb, 0x99,
          0x25, 0xc0, 0x02, 0x54, 0xf2, 0x48, 0x93, 0x27,
          0xb6, 0x40, 0xb7, 0xb2, 0x0f, 0x91, 0x00, 0x00,
          0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x01, 0x00, 0x02, 0x00
        ];

        byte[] preAuthSalt = [
          0xc2, 0x08, 0xbe, 0xc6, 0xb2, 0xe6, 0x6b, 0x57,
          0x96, 0x5e, 0xf8, 0x92, 0x2e, 0xc8, 0xb9, 0xff,
          0xeb, 0x99, 0x25, 0xc0, 0x02, 0x54, 0xf2, 0x48,
          0x93, 0x27, 0xb6, 0x40, 0xb7, 0xb2, 0x0f, 0x91
        ];

        NegotiateResponse sut = new();
        sut.Header.CreditCharge = 0;
        sut.Header.Status = NTStatus.STATUS_SUCCESS;
        sut.Header.Credits = 1;
        sut.Header.MessageID = 1;
        sut.Header.Reserved = 0xfeff;
        sut.SecurityMode = SecurityMode.SigningEnabled;
        sut.DialectRevision = Smb2Dialect.SMB311;
        sut.ServerGuid = new Guid("a3af6e96-7f35-4004-a5f9-643e1bfa8c56");
        sut.Capabilities = Capabilities.DFS | Capabilities.Leasing | Capabilities.LargeMTU |
            Capabilities.MultiChannel | Capabilities.DirectoryLeasing;
        sut.MaxTransactSize = 8388608;
        sut.MaxReadSize = 8388608;
        sut.MaxWriteSize = 8388608;
        sut.SystemTime = new DateTime(2016, 10, 16, 8, 16, 1, 36, 877, DateTimeKind.Utc).AddNanoseconds(900);
        sut.ServerStartTime = new DateTime(2016, 10, 16, 8, 8, 51, 272, 182, DateTimeKind.Utc).AddNanoseconds(500);
        sut.SecurityBuffer = securityBlob;
        sut.NegotiateContextList =
        [
            new PreAuthIntegrityCapabilities
            {
                Reserved = 0,
                HashAlgorithms = [HashAlgorithm.SHA512],
                Salt = preAuthSalt,
            },
            new EncryptionCapabilities
            {
                Reserved = 0,
                Ciphers = [CipherAlgorithm.Aes128Gcm],
            }
        ];


        byte[] actualBytes = sut.GetBytes(Smb2Dialect.SMB311);

        actualBytes.Should().Equal(expectedBytes);
    }
}