using Lansweeper.Smb.Enums;
using Lansweeper.Smb.SMB2;
using Lansweeper.Smb.SMB2.Enums;

namespace Lansweeper.SMB.Tests.SMB2;

class Smb2HeaderShould
{
    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer_Dialect311SyncRequest()
    {
        // Arrange
        byte[] buffer =
        [
            0xfe, 0x53, 0x4d, 0x42, // Protocol Id
            0x40, 0x00, // StructureSize
            0x01, 0x00, // CreditCharge
            0x02, 0x00, // ChannelSequence
            0x00, 0x00, // ChannelSequenceReserved
            0x01, 0x00, // Command
            0x1f, 0x00, // CreditRequest
            0x10, 0x00, 0x00, 0x00, // Flags
            0x00, 0x00, 0x00, 0x00, // NextCommand
            0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // MessageId
            0xff, 0xfe, 0x00, 0x00, // Reserved
            0x01, 0x00, 0x00, 0x00, // TreeId
            0x01, 0x00, 0x00, 0x00, 
            0x00, 0x74, 0x00, 0x00, // SessionId
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00  // Signature
        ];

        byte[] expectedSignature = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // Act
        var sut = new Smb2Header(buffer, Smb2Dialect.SMB311);

        // Assert
        sut.CreditCharge.Should().Be(1);
        sut.Status.Should().Be(NTStatus.STATUS_SUCCESS);// should not be set
        sut.ChannelSequence.Should().Be(2); // should be set
        sut.ChannelSequenceReserved.Should().Be(0);
        sut.Command.Should().Be(Smb2CommandName.SessionSetup);
        sut.Credits.Should().Be(31);
        sut.Flags.Should().Be(Smb2PacketHeaderFlags.Priority1);
        sut.NextCommand.Should().Be(0);
        sut.MessageID.Should().Be(3);
        sut.Reserved.Should().Be(0xfeff); // weird value, but this is what we got from wireshark
        sut.TreeID.Should().Be(1);
        sut.SessionID.Should().Be(0x0000740000000001);
        sut.Signature.Should().Equal(expectedSignature);

        sut.IsResponse.Should().BeFalse();
        sut.IsAsync.Should().BeFalse();
        sut.IsRelatedOperations.Should().BeFalse();
        sut.IsSigned.Should().BeFalse();
        sut.Priority.Should().Be(1);
    }

    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer_Dialect311SyncResponse()
    {
        // Arrange
        byte[] buffer =
        [
            0xfe, 0x53, 0x4d, 0x42, // Protocol Id
            0x40, 0x00, // StructureSize
            0x01, 0x00, // CreditCharge
            0x6d, 0x00, 0x00, 0xc0, // Status
            0x01, 0x00, // Command
            0x01, 0x00, // Credit granted
            0x11, 0x00, 0x00, 0x00, // Flags
            0x00, 0x00, 0x00, 0x00, // NextCommand
            0x03, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, // MessageId
            0xff, 0xfe, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x00, 0x00, // TreeId
            0x01, 0x00, 0x00, 0x00, 
            0x00, 0x74, 0x00, 0x00, // SessionId
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00  // Signature
        ];

        byte[] expectedSignature = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // Act
        var sut = new Smb2Header(buffer, Smb2Dialect.SMB311);

        // Assert
        sut.CreditCharge.Should().Be(1);
        sut.Status.Should().Be(NTStatus.STATUS_LOGON_FAILURE);
        sut.ChannelSequence.Should().Be(0); // should not be set
        sut.ChannelSequenceReserved.Should().Be(0);
        sut.Command.Should().Be(Smb2CommandName.SessionSetup);
        sut.Credits.Should().Be(1);
        sut.Flags.Should().Be(Smb2PacketHeaderFlags.Priority1 | Smb2PacketHeaderFlags.ServerToRedir);
        sut.NextCommand.Should().Be(0);
        sut.MessageID.Should().Be(3);
        sut.Reserved.Should().Be(0xfeff); // weird value, but this is what we got from wireshark
        sut.TreeID.Should().Be(0);
        sut.SessionID.Should().Be(0x0000740000000001);
        sut.Signature.Should().Equal(expectedSignature);

        sut.IsResponse.Should().BeTrue();
        sut.IsAsync.Should().BeFalse();
        sut.IsRelatedOperations.Should().BeFalse();
        sut.IsSigned.Should().BeFalse();
        sut.Priority.Should().Be(1);
    }

    // TODO find async examples and other dialects

    [Test]
    public void WriteBytesCorrectly()
    {
        byte[] expectedBytes =
        [
            0xfe, 0x53, 0x4d, 0x42, // Protocol Id
            0x40, 0x00, // StructureSize
            0x01, 0x00, // CreditCharge
            0x02, 0x00, // ChannelSequence
            0x00, 0x00, // ChannelSequenceReserved
            0x01, 0x00, // Command
            0x1f, 0x00, // CreditRequest
            0x10, 0x00, 0x00, 0x00, // Flags
            0x00, 0x00, 0x00, 0x00, // NextCommand
            0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // MessageId
            0xff, 0xfe, 0x00, 0x00, // Reserved
            0x01, 0x00, 0x00, 0x00, // TreeId
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x74, 0x00, 0x00, // SessionId
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00  // Signature
        ];

        var sut = new Smb2Header(Smb2CommandName.SessionSetup)
        {
            CreditCharge = 1,
            ChannelSequence = 2,
            Command = Smb2CommandName.SessionSetup,
            Credits = 31,
            Priority = 1,
            IsAsync = false,
            MessageID = 3,
            Reserved = 0xfeff,
            TreeID = 1,
            SessionID = 0x0000740000000001,
        };

        // Act
        byte[] actualBytes = new byte[expectedBytes.Length];
        sut.WriteBytes(actualBytes, Smb2Dialect.SMB311);

        // Assert
        actualBytes.Should().Equal(expectedBytes);
    }


    [TestCase(new byte[] { 0xFE, 0x53, 0x4D, 0x42 }, ExpectedResult = true)] // SMB2
    [TestCase(new byte[] { 0xFF, 0x53, 0x4D, 0x42 }, ExpectedResult = false)] // SMB1
    public bool RecognizeValidHeader(byte[] input)
    {
        return Smb2Header.IsValidSMB2Header(input);
    }


}
