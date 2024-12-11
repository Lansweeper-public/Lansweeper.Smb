using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.SMB.Tests.Netbios;

[TestFixture]
public class ResourceRecordShould
{
    [Test]
    public void ConstructPropertiesCorrectly()
    {
        // Arrange
        var type = NameRecordType.NB;

        // Act
        var resourceRecord = new ResourceRecord(type);

        // Assert
        resourceRecord.Type.Should().Be(type);
        resourceRecord.Name.Should().BeEmpty();
        resourceRecord.Class.Should().Be(ResourceRecordClass.In);
        resourceRecord.TTL.Should().Be((uint)new TimeSpan(7, 0, 0, 0).TotalSeconds);
        resourceRecord.Data.Should().BeEmpty();
    }

    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // Arrange
        var name = "TEST".PadRight(16);
        var type = NameRecordType.NB;
        var classValue = ResourceRecordClass.In;
        var ttl = (uint)new TimeSpan(7, 0, 0, 0).TotalSeconds;
        var data = new byte[] { 1, 2, 3, 4 };

        byte[] buffer = [
                ..NetBiosUtils.EncodeName(name, string.Empty), // Name
                0x00, 0x20, // Type
                0x00, 0x01, // Class
                0x00, 0x09, 0x3a, 0x80, // TTL
                0x00, 0x04, // Data length
                0x01, 0x02, 0x03, 0x04 // Data
            ];

        // Act
        var resourceRecord = new ResourceRecord(buffer);

        // Assert
        resourceRecord.Name.Should().Be(name);
        resourceRecord.Type.Should().Be(type);
        resourceRecord.Class.Should().Be(classValue);
        resourceRecord.TTL.Should().Be(ttl);
        resourceRecord.Data.Should().Equal(data);
    }

    [Test]
    public void WriteBytesToStreamCorrectly()
    {
        // Arrange
        var name = "TEST".PadRight(16);
        var type = NameRecordType.NB;
        var data = new byte[] { 1, 2, 3, 4 };
        var resourceRecord = new ResourceRecord(type, name)
        {
            Data = data,
        };

        byte[] expectedBuffer = [
                ..NetBiosUtils.EncodeName(name, string.Empty), // Name
                0x00, 0x20, // Type
                0x00, 0x01, // Class
                0x00, 0x09, 0x3a, 0x80, // TTL
                0x00, 0x04, // Data length
                0x01, 0x02, 0x03, 0x04 // Data
            ];

        // Act
        using var stream = new MemoryStream();
        resourceRecord.WriteBytes(stream);

        // Assert
        stream.ToArray().Should().Equal(expectedBuffer);
    }
}
