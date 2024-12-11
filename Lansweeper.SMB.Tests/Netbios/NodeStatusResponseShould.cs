using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.SMB.Tests.Netbios;

public class NodeStatusResponseShould
{
    [Test]
    public void ConstructPropertiesCorrectly()
    {
        // Arrange
        ushort transactionId = 0x1234;
        string name = NetBiosUtils.GetMSNetBiosName("testname", NetBiosSuffix.WorkstationService);

        // Act
        var nodeStatusResponse = new NodeStatusResponse(transactionId, name);

        // Assert
        nodeStatusResponse.Header.TransactionID.Should().Be(0x1234);
        nodeStatusResponse.Header.OpCode.Should().Be(NameServiceOperation.QueryResponse);
        nodeStatusResponse.Header.Flags.Should().Be(OperationFlags.AuthoritativeAnswer);
        nodeStatusResponse.Header.ResultCode.Should().Be(0);
        nodeStatusResponse.Header.QDCount.Should().Be(0);
        nodeStatusResponse.Header.ANCount.Should().Be(1);
        nodeStatusResponse.Header.NSCount.Should().Be(0);
        nodeStatusResponse.Header.ARCount.Should().Be(0);
        nodeStatusResponse.Resource.Name.Should().Be(name);
        nodeStatusResponse.Resource.Type.Should().Be(NameRecordType.NBStat);
        nodeStatusResponse.Resource.Class.Should().Be(ResourceRecordClass.In);
        nodeStatusResponse.Names.Should().BeEmpty();
        nodeStatusResponse.Statistics.Should().NotBeNull();
    }

    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // Arrange
        byte[] buffer = [
            0x12, 0x34, // TransactionID
            0x84, 0x00, // OpCode, Flags and ResultCode
            0x00, 0x00, // QDCount
            0x00, 0x01, // ANCount
            0x00, 0x00, // NSCount
            0x00, 0x00, // ARCount
            0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, // RRName
            0x00, 0x21, // Type
            0x00, 0x01, // Class
            0x00, 0x00, 0x00, 0x00, // TTL
            0x00, 0x65, // Data Length
            0x03, // Number of names
            0x43, 0x4f, 0x4e, 0x48, 0x51, 0x57, 0x45, 0x58, 0x30, 0x33, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, // Name1
            0x04, 0x00, // Name1 flags
            0x43, 0x4f, 0x4e, 0x54, 0x4f, 0x53, 0x4f, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, // Name2
            0x84, 0x00, // Name2 flags
            0x43, 0x4f, 0x4e, 0x48, 0x51, 0x57, 0x45, 0x58, 0x30, 0x33, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // Name3
            0x04, 0x00, // Name 3 flags
            0x00, 0x50, 0x56, 0x87, 0x9d, 0x35, // Unit ID
            0x00, // Jumpers
            0x00, // Test result
            0x00, 0x00, // Version number
            0x00, 0x00, // Period of statistics
            0x00, 0x00, // Number of CRCs
            0x00, 0x00, // Number of alignment errors
            0x00, 0x00, // Number of collisions
            0x00, 0x00, // Number of send aborts
            0x00, 0x00, 0x00, 0x00, // Number of good sends
            0x00, 0x00, 0x00, 0x00, // Number of good receives
            0x00, 0x00, // Number of retransmits
            0x00, 0x00, // Number of no resource conditions
            0x00, 0x00, // Number of command blocks
            0x00, 0x00, // Number of pending sessions
            0x00, 0x00, // Max number of pending sessions
            0x00, 0x00, // Max total sessions possible
            0x00, 0x00, // Session data packet size
            0x00, 0x00, 0x00, 0x00, // some junk at the end??
            ];

        // Act
        var nodeStatusResponse = new NodeStatusResponse(buffer);

        // Assert
        var header = nodeStatusResponse.Header;
        header.TransactionID.Should().Be(0x1234);
        header.OpCode.Should().Be(NameServiceOperation.QueryResponse);
        header.Flags.Should().Be(OperationFlags.AuthoritativeAnswer);
        header.ResultCode.Should().Be(0);
        header.QDCount.Should().Be(0);
        header.ANCount.Should().Be(1);
        header.NSCount.Should().Be(0);
        header.ARCount.Should().Be(0);

        var resource = nodeStatusResponse.Resource;
        resource.Name.Should().Be("*".PadRight(16, '\0'));
        resource.Type.Should().Be(NameRecordType.NBStat);
        resource.Class.Should().Be(ResourceRecordClass.In);
        resource.TTL.Should().Be(0);
        resource.Data.Length.Should().Be(101);

        var names = nodeStatusResponse.Names;
        names.Count.Should().Be(3);
        names[0].Key.Should().Be("CONHQWEX03     \0");
        names[0].Value.Type.Should().Be(OwnerNodeType.BNode);
        names[0].Value.IsGroupName.Should().BeFalse();
        names[1].Key.Should().Be("CONTOSO        \0");
        names[1].Value.Type.Should().Be(OwnerNodeType.BNode);
        names[1].Value.IsGroupName.Should().BeTrue();
        names[2].Key.Should().Be("CONHQWEX03      ");
        names[2].Value.Type.Should().Be(OwnerNodeType.BNode);
        names[2].Value.IsGroupName.Should().BeFalse();

        nodeStatusResponse.Statistics.Should().NotBeNull();
    }

    [Test]
    public void GetBytesCorrectly()
    {
        // Arrange
        ushort transactionId = 0x1234;
        string name = NetBiosUtils.GetMSNetBiosName("testname", NetBiosSuffix.WorkstationService);
        var nodeStatusResponse = new NodeStatusResponse(transactionId, name);
        nodeStatusResponse.Names.Add("CONHQWEX03     \0", new NameFlags(false, OwnerNodeType.BNode, false, false, true, false));
        nodeStatusResponse.Names.Add("CONTOSO        \0", new NameFlags(true, OwnerNodeType.BNode, false, false, true, false));
        nodeStatusResponse.Names.Add("CONHQWEX03      ", new NameFlags(false, OwnerNodeType.BNode, false, false, true, false));

        byte[] expectedBytes = [
            0x12, 0x34, // TransactionID
            0x84, 0x00, // OpCode, Flags and ResultCode
            0x00, 0x00, // QDCount
            0x00, 0x01, // ANCount
            0x00, 0x00, // NSCount
            0x00, 0x00, // ARCount
            ..NetBiosUtils.EncodeName(name, ""),
            //0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, // RRName
            0x00, 0x21, // Type
            0x00, 0x01, // Class
            0x00, 0x09, 0x3A, 0x80, // TTL
            0x00, 0x65, // Data Length
            0x03, // Number of names
            0x43, 0x4f, 0x4e, 0x48, 0x51, 0x57, 0x45, 0x58, 0x30, 0x33, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, // Name1
            0x04, 0x00, // Name1 flags
            0x43, 0x4f, 0x4e, 0x54, 0x4f, 0x53, 0x4f, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, // Name2
            0x84, 0x00, // Name2 flags
            0x43, 0x4f, 0x4e, 0x48, 0x51, 0x57, 0x45, 0x58, 0x30, 0x33, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // Name3
            0x04, 0x00, // Name 3 flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Unit ID
            0x00, // Jumpers
            0x00, // Test result
            0x00, 0x00, // Version number
            0x00, 0x00, // Period of statistics
            0x00, 0x00, // Number of CRCs
            0x00, 0x00, // Number of alignment errors
            0x00, 0x00, // Number of collisions
            0x00, 0x00, // Number of send aborts
            0x00, 0x00, 0x00, 0x00, // Number of good sends
            0x00, 0x00, 0x00, 0x00, // Number of good receives
            0x00, 0x00, // Number of retransmits
            0x00, 0x00, // Number of no resource conditions
            0x00, 0x00, // Number of free command blocks
            0x00, 0x00, // Total number of command blocks
            0x00, 0x00, // Max total number of command blocks
            0x00, 0x00, // Number of pending sessions
            0x00, 0x00, // Max number of pending sessions
            0x00, 0x00, // Max total sessions possible
            0x00, 0x00, // Session data packet size
            ];

        // Act
        var resultBytes = nodeStatusResponse.GetBytes();

        // Assert
        resultBytes.Should().Equal(expectedBytes);
    }
}
