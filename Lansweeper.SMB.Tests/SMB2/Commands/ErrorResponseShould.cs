﻿using Lansweeper.Smb.Enums;
using Lansweeper.Smb.SMB2.Commands;
using Lansweeper.Smb.SMB2.Enums;

namespace Lansweeper.SMB.Tests.SMB2.Commands;

internal class ErrorResponseShould
{
    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        byte[] buffer = [
          0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
          0x6d, 0x00, 0x00, 0xc0, 0x01, 0x00, 0x01, 0x00,
          0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x25, 0x00, 0x00, 0x0c, 0x00, 0xec, 0x01, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        ErrorResponse sut = new(buffer, Smb2Dialect.SMB311);

        sut.Header.Status.Should().Be(NTStatus.STATUS_LOGON_FAILURE);
        sut.ErrorContextCount.Should().Be(0);
        sut.Reserved.Should().Be(0);
        sut.ErrorData.Should().BeEmpty();
    }

    // TODO find example of buffer with ErrorData

    [Test]
    public void GetBytesCorrectly()
    {
        byte[] expectedBytes = [
          0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
          0x6d, 0x00, 0x00, 0xc0, 0x01, 0x00, 0x01, 0x00,
          0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x25, 0x00, 0x00, 0x0c, 0x00, 0xec, 0x01, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        ErrorResponse sut = new(Smb2CommandName.SessionSetup, NTStatus.STATUS_LOGON_FAILURE);
        sut.Header.CreditCharge = 1;
        sut.Header.Credits = 1;
        sut.Header.Priority = 1;
        sut.Header.MessageID = 4;
        sut.Header.Reserved = 0xfeff;
        sut.Header.SessionID = 0x0001ec000c000025;
        byte[] actualBytes = sut.GetBytes(Smb2Dialect.SMB311);

        actualBytes.Should().Equal(expectedBytes);
    }
}
