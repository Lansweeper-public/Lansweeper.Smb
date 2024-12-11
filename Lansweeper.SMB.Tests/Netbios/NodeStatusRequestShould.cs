using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.Netbios.Enums;
using System.Buffers.Binary;

namespace Lansweeper.SMB.Tests.Netbios;

[TestFixture]
public class NodeStatusRequestShould
{
    [Test]
    public void ConstructPropertiesCorrectly()
    {
        // Arrange
        var questionName = "TEST".PadRight(16);

        // Act
        var nodeStatusRequest = new NodeStatusRequest(questionName);

        // Assert
        nodeStatusRequest.Header.TransactionID.Should().NotBe(0);
        nodeStatusRequest.Header.Flags.Should().Be(OperationFlags.None);
        nodeStatusRequest.Header.OpCode.Should().Be(NameServiceOperation.QueryRequest);
        nodeStatusRequest.Header.ResultCode.Should().Be(0);
        nodeStatusRequest.Header.QDCount.Should().Be(1);
        nodeStatusRequest.Header.ANCount.Should().Be(0);
        nodeStatusRequest.Header.NSCount.Should().Be(0);
        nodeStatusRequest.Header.ARCount.Should().Be(0);
        nodeStatusRequest.Question.Name.Should().Be(questionName);
        nodeStatusRequest.Question.Type.Should().Be(NameRecordType.NBStat);
        nodeStatusRequest.Question.Class.Should().Be(QuestionClass.In);
    }

    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // Arrange
        var questionName = "TEST".PadRight(16);

        byte[] buffer = [
                0x12, 0x34, // TransactionID
                0x00, 0x00, // OpCode, Flags and ResultCode // assumes unicast
                0x00, 0x01, // QDCount
                0x00, 0x00, // ANCount
                0x00, 0x00, // NSCount
                0x00, 0x00, // ARCount
                ..NetBiosUtils.EncodeName(questionName, string.Empty), // Name
                0x00, 0x21, // Type
                0x00, 0x01 // Class
            ];

        // Act
        var nodeStatusRequest = new NodeStatusRequest(buffer);

        // Assert
        nodeStatusRequest.Header.TransactionID.Should().Be(0x1234);
        nodeStatusRequest.Header.OpCode.Should().Be(NameServiceOperation.QueryRequest);
        nodeStatusRequest.Header.Flags.Should().Be(OperationFlags.None);
        nodeStatusRequest.Header.ResultCode.Should().Be(0);
        nodeStatusRequest.Header.QDCount.Should().Be(1);
        nodeStatusRequest.Header.ANCount.Should().Be(0);
        nodeStatusRequest.Header.NSCount.Should().Be(0);
        nodeStatusRequest.Header.ARCount.Should().Be(0);
        nodeStatusRequest.Question.Name.Should().Be(questionName);
        nodeStatusRequest.Question.Type.Should().Be(NameRecordType.NBStat);
        nodeStatusRequest.Question.Class.Should().Be(QuestionClass.In);
    }

    [Test]
    public void GetBytesCorrectly()
    {
        // Arrange
        var questionName = "TEST".PadRight(16);
        var nodeStatusRequest = new NodeStatusRequest(questionName);

        Span<byte> transActionIdAsBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(transActionIdAsBytes, nodeStatusRequest.Header.TransactionID);

        byte[] expectedBytes = [
                ..transActionIdAsBytes, // TransactionID
                0x00, 0x00, // OpCode, Flags and ResultCode // assumes unicast
                0x00, 0x01, // QDCount
                0x00, 0x00, // ANCount
                0x00, 0x00, // NSCount
                0x00, 0x00, // ARCount
                ..NetBiosUtils.EncodeName(questionName, string.Empty), // Name
                0x00, 0x21, // Type
                0x00, 0x01 // Class
            ];


        // Act
        var resultBytes = nodeStatusRequest.GetBytes();

        // Assert
        resultBytes.Should().Equal(expectedBytes);
    }
}
