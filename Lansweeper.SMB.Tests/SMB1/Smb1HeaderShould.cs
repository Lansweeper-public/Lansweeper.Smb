using Lansweeper.Smb.SMB1;
using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Enums;

namespace Lansweeper.SMB.Tests.SMB1;

public class Smb1HeaderShould
{
    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // Arrange
        byte[] buffer =
        [
            0xff, 0x53, 0x4d, 0x42, // Protocol
            0x73, // Command
            0x00, 0x00, 0x00, 0x00, // Status
            0x08, // Flags
            0x03, 0xc8, // Flags2
            0x00, 0x00, // PIDHigh
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SecurityFeatures
            0x00, 0x00, // Reserved
            0x00, 0x00, // TID
            0x43, 0x79, // PIDLow
            0x00, 0x00, // UID
            0x02, 0x00  // MID
        ];

        // Act
        var sut = new Smb1Header(buffer);

        // Assert
        sut.Command.Should().Be(CommandName.SMB_COM_SESSION_SETUP_ANDX);
        sut.Status.Should().Be(NTStatus.STATUS_SUCCESS);
        sut.Flags.Should().Be(HeaderFlags.CaseInsensitive);
        sut.Flags2.Should().Be(HeaderFlags2.Unicode | HeaderFlags2.NTStatusCode | HeaderFlags2.ExtendedSecurity | HeaderFlags2.ExtendedAttributes | HeaderFlags2.LongNamesAllowed);
        sut.SecurityFeatures.Should().Be(0x0000000000000000);
        sut.TID.Should().Be(0);
        sut.PID.Should().Be(31043);
        sut.UID.Should().Be(0);
        sut.MID.Should().Be(2);
    }

    [TestCase(new byte[] {
          0xff, 0x53, 0x4d, 0x42, 0x73, 0x00, 0x00, 0x00,  0x00, 0x08, 0x03, 0xc8, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x43, 0x79, 0x00, 0x00, 0x02, 0x00
    }, true)]
    [TestCase(new byte[] {
          0xff, 0x53, 0x4e, 0x42, 0x73, 0x00, 0x00, 0x00,  0x00, 0x08, 0x03, 0xc8, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x43, 0x79, 0x00, 0x00, 0x02, 0x00
    }, false)]
    public void CheckForValidSmb1Header(byte[] buffer, bool expected)
    {
        // Act
        bool actual = Smb1Header.IsValidSMB1Header(buffer);

        // Assert
        actual.Should().Be(expected);
    }

    [Test]
    public void WriteBytesCorrectly()
    {
        // Arrange
        byte[] expectedBytes =
        [
            0xff, 0x53, 0x4d, 0x42, // Protocol
            0x73, // Command
            0x00, 0x00, 0x00, 0x00, // Status
            0x08, // Flags
            0x03, 0xc8, // Flags2
            0x00, 0x00, // PIDHigh
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SecurityFeatures
            0x00, 0x00, // Reserved
            0x00, 0x00, // TID
            0x43, 0x79, // PIDLow
            0x00, 0x00, // UID
            0x02, 0x00  // MID
        ];

        var sut = new Smb1Header()
        {
            Command = CommandName.SMB_COM_SESSION_SETUP_ANDX,
            Status = NTStatus.STATUS_SUCCESS,
            Flags = HeaderFlags.CaseInsensitive,
            Flags2 = HeaderFlags2.Unicode | HeaderFlags2.NTStatusCode | HeaderFlags2.ExtendedSecurity | HeaderFlags2.ExtendedAttributes | HeaderFlags2.LongNamesAllowed,
            SecurityFeatures = 0x0000000000000000,
            TID = 0,
            PID = 31043,
            UID = 0,
            MID = 2
        };

        // Act
        byte[] actualBytes = new byte[expectedBytes.Length];
        sut.WriteBytes(actualBytes);

        // Assert
        actualBytes.Should().Equal(expectedBytes);
    }

}
