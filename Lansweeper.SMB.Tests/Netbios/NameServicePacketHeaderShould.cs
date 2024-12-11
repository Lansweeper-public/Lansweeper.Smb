using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.SMB.Tests.Netbios;

public class NameServicePacketHeaderShould
{
    [Test]
    public void ConstructPropertiesCorrectly()
    {
        // Arrange
        byte[] buffer = [
            0x12, 0x34, // TransactionID
            0xB4, 0x18, // OpCOde, Flags and ResultCode
            0x9A, 0xBC, // QDCount
            0xDE, 0xF0, // ANCount
            0x12, 0x34, // NSCount
            0x56, 0x78, // ARCount
            ];

        // Act
        var header = new NameServicePacketHeader(buffer);

        // Assert
        header.TransactionID.Should().Be(0x1234);
        header.OpCode.Should().Be(NameServiceOperation.ReleaseResponse);
        header.Flags.Should().Be(OperationFlags.AuthoritativeAnswer | OperationFlags.Broadcast);
        header.ResultCode.Should().Be(0x8);
        header.QDCount.Should().Be(0x9ABC);
        header.ANCount.Should().Be(0xDEF0);
        header.NSCount.Should().Be(0x1234);
        header.ARCount.Should().Be(0x5678);
    }

    [Test]
    public void ShouldWriteBytesToStreamCorrecty()
    {
        // Arrange
        var header = new NameServicePacketHeader
        {
            TransactionID = 0x1234,
            OpCode = NameServiceOperation.ReleaseResponse,
            Flags = OperationFlags.AuthoritativeAnswer | OperationFlags.Broadcast,
            ResultCode = 0x8,
            QDCount = 0x9ABC,
            ANCount = 0xDEF0,
            NSCount = 0x1234,
            ARCount = 0x5678
        };

        byte[] expected = [
            0x12, 0x34, // TransactionID
            0xB4, 0x18, // OpCOde, Flags and ResultCode
            0x9A, 0xBC, // QDCount
            0xDE, 0xF0, // ANCount
            0x12, 0x34, // NSCount
            0x56, 0x78, // ARCount
            ];

        // Act
        using var stream = new MemoryStream();
        header.WriteBytes(stream);

        // Assert
        stream.ToArray().Should().Equal(expected);
    }
}
