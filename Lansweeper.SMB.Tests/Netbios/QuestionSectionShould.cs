using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.SMB.Tests.Netbios;

public class QuestionSectionShould
{
    [Test]
    public void ConstructPropertiesCorrectly()
    {
        // Arrange
        var type = NameRecordType.NB;
        var name = "TEST".PadRight(16);

        // Act
        var questionSection = new QuestionSection(type, name);

        // Assert
        questionSection.Type.Should().Be(type);
        questionSection.Name.Should().Be(name);
        questionSection.Class.Should().Be(QuestionClass.In);
    }

    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // Arrange
        var name = "TEST".PadRight(16);
        var type = NameRecordType.NB;
        var classValue = QuestionClass.In;

        byte[] buffer = [
                ..NetBiosUtils.EncodeName(name, string.Empty), // Name
                0x00, 0x20, // Type
                0x00, 0x01 // Class
            ];

        // Act
        var questionSection = new QuestionSection(buffer);

        // Assert
        questionSection.Name.Should().Be(name);
        questionSection.Type.Should().Be(type);
        questionSection.Class.Should().Be(classValue);
    }

    [Test]
    public void WriteBytesToStreamCorrecty()
    {
        // Arrange
        var name = "TEST".PadRight(16);
        var questionSection = new QuestionSection(NameRecordType.NB, name);

        byte[] expected = [
                ..NetBiosUtils.EncodeName(name, string.Empty), // Name
                0x00, 0x20, // Type
                0x00, 0x01 // Class
            ];

        // Act
        using var stream = new MemoryStream();
        questionSection.WriteBytes(stream);

        // Assert
        stream.ToArray().Should().Equal(expected);
    }
}
