using Lansweeper.Smb.SMB1.Commands;

namespace Lansweeper.SMB.Tests.SMB1.Commands;

public class NegotiateRequestShould
{
    [Test]
    public void ConstructPropertiesCorrectly()
    {
        // Arrange
        var dialects = new List<string> { "NT LM 0.12", "SMB 2.002" };

        // Act
        var negotiateRequest = new NegotiateRequest();
        negotiateRequest.Dialects.AddRange(dialects);

        // Assert
        negotiateRequest.Dialects.Should().BeEquivalentTo(dialects);
    }

    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // Arrange
        byte[] buffer = [
            0x00, // Word Count (should always be 0)
            0x9b, 0x00, // Byte Count
            // dialect1
            0x02, 0x50, 0x43, 0x20, 0x4e,
            0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50,
            0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31,
            0x2e, 0x30, 0x00,
            // dialect2
            0x02, 0x4d, 0x49, 0x43, 0x52,
            0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45,
            0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20, 0x31,
            0x2e, 0x30, 0x33, 0x00, 
            // dialect3
            0x02, 0x4d, 0x49, 0x43,
            0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e,
            0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20,
            0x33, 0x2e, 0x30, 0x00,
            // dialect4
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 
            //dialect5
            0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30,
            0x32, 0x00,
            // dialect6
            0x02, 0x44, 0x4f, 0x53, 0x20, 0x4c,
            0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31,
            0x00,
            // dialect7
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e,
            0x32, 0x2e, 0x31, 0x00,
            // dialect8
            0x02, 0x53, 0x61, 0x6d, 0x62, 0x61, 0x00,
            // dialect9
            0x02, 0x4e, 0x54, 0x20, 0x4c,
            0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e,
            0x30, 0x00,
            // dialect10
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d,
            0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
         ];

        List<string> expectedDialects = [
            "PC NETWORK PROGRAM 1.0",
            "MICROSOFT NETWORKS 1.03",
            "MICROSOFT NETWORKS 3.0",
            "LANMAN1.0",
            "LM1.2X002",
            "DOS LANMAN2.1",
            "LANMAN2.1",
            "Samba",
            "NT LANMAN 1.0",
            "NT LM 0.12"
        ];

        // Act
        var negotiateRequest = new NegotiateRequest(buffer);

        // Assert
        negotiateRequest.Dialects.Should().Equal(expectedDialects);
    }

    [Test]
    public void GetBytesCorrectly()
    {
        // Arrange
        // Arrange
        byte[] expectedBytes = [
            0x00, // Word Count (should always be 0)
            0x9b, 0x00, // Byte Count
            // dialect1
            0x02, 0x50, 0x43, 0x20, 0x4e,
            0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50,
            0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31,
            0x2e, 0x30, 0x00,
            // dialect2
            0x02, 0x4d, 0x49, 0x43, 0x52,
            0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45,
            0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20, 0x31,
            0x2e, 0x30, 0x33, 0x00, 
            // dialect3
            0x02, 0x4d, 0x49, 0x43,
            0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e,
            0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20,
            0x33, 0x2e, 0x30, 0x00,
            // dialect4
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 
            //dialect5
            0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30,
            0x32, 0x00,
            // dialect6
            0x02, 0x44, 0x4f, 0x53, 0x20, 0x4c,
            0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31,
            0x00,
            // dialect7
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e,
            0x32, 0x2e, 0x31, 0x00,
            // dialect8
            0x02, 0x53, 0x61, 0x6d, 0x62, 0x61, 0x00,
            // dialect9
            0x02, 0x4e, 0x54, 0x20, 0x4c,
            0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e,
            0x30, 0x00,
            // dialect10
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d,
            0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
         ];

        List<string> dialects = [
            "PC NETWORK PROGRAM 1.0",
            "MICROSOFT NETWORKS 1.03",
            "MICROSOFT NETWORKS 3.0",
            "LANMAN1.0",
            "LM1.2X002",
            "DOS LANMAN2.1",
            "LANMAN2.1",
            "Samba",
            "NT LANMAN 1.0",
            "NT LM 0.12"
        ];

        NegotiateRequest sut = new();
        sut.Dialects.AddRange(dialects);

        // Act
        var resultBytes = sut.GetBytes(false);

        // Assert
        resultBytes.Should().Equal(expectedBytes);
    }
}
