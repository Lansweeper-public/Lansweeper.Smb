using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.Smb.Tests.Netbios;

public class NameFlagsShould
{
    [TestCase(new byte[] { 0b1100_0100, 0x00 }, OwnerNodeType.MNode, true, false, false, true, false)]
    [TestCase(new byte[] { 0b1001_0110, 0x00 }, OwnerNodeType.BNode, true, true, false, true, true)]
    [TestCase(new byte[] { 0b0010_1110, 0x00 }, OwnerNodeType.PNode, false, false, true, true, true)]
    public void SetPropertiesCorrectlyFromConstructorWithBuffer(byte[] buffer, OwnerNodeType type, bool isGroupName, bool isBeingDeleted, bool isInConflict, bool isActiveName, bool isPermanent)
    {
        // Act
        var nameFlags = new NameFlags(buffer);

        // Assert
        nameFlags.IsGroupName.Should().Be(isGroupName);
        nameFlags.Type.Should().Be(type);
        nameFlags.IsBeingDeleted.Should().Be(isBeingDeleted);
        nameFlags.IsInConflict.Should().Be(isInConflict);
        nameFlags.IsActiveName.Should().Be(isActiveName);
        nameFlags.IsPermanent.Should().Be(isPermanent);
    }

    [TestCase(new byte[] { 0b1100_0100, 0x00 }, OwnerNodeType.MNode, true, false, false, true, false)]
    [TestCase(new byte[] { 0b1001_0110, 0x00 }, OwnerNodeType.BNode, true, true, false, true, true)]
    [TestCase(new byte[] { 0b0010_1110, 0x00 }, OwnerNodeType.PNode, false, false, true, true, true)]
    public void WriteBytesCorrecty(byte[] expected, OwnerNodeType type, bool isGroupName, bool isBeingDeleted, bool isInConflict, bool isActiveName, bool isPermanent)
    {
        // Arrange
        var nameFlags = new NameFlags(isGroupName,type,isBeingDeleted,isInConflict,isActiveName,isPermanent);
        using var stream = new MemoryStream();

        // Act
        nameFlags.WriteBytes(stream);
        byte[] result = stream.ToArray();

        // Assert
        result.Should().HaveCount(2);
        result[0].Should().Be(expected[0]);
        result[1].Should().Be(expected[1]).And.Be(0); // Second byte should always be 0
    }

}
