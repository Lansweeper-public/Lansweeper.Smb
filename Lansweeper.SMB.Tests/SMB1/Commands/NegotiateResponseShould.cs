using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;

namespace Lansweeper.SMB.Tests.SMB1.Commands;

/// <remarks>
/// The byte arrays here are constructed manually based on the specification. No example packet captures were found so far.
/// </remarks>
public class NegotiateResponseShould
{
    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // Arrange
        byte[] buffer = [
            0x11, // Word Count
            0x08, 0x00, // Selected Dialect Index
            0x03, // Security Mode
            0x32, 0x00, // Max Mpx Count
            0x01, 0x00, // Max Number Vcs
            0x04, 0x41, 0x00, 0x00, // Max Buffer Size
            0x00, 0x00, 0x01, 0x00, // Max Raw Buffer
            0x19, 0x1e, 0x00, 0x00, // Session Key
            0xfd, 0xf3, 0x80, 0x00, // Capabilities
            0x80, 0x4d, 0x8e, 0xd1, 0xfa, 0x20, 0xce, 0x01, // System Time
            0x00, 0x00, // Server Time Zone
            0x00, // Challenge Length 
            0x1c, 0x00, // Byte Count
            0x44, 0x00, 0x4F, 0x00,
            0x4D, 0x00, 0x41, 0x00,
            0x49, 0x00, 0x4E, 0x00,
            0x00, 0x00, // Domain Name
            0x53, 0x00, 0x45, 0x00,
            0x52, 0x00, 0x56, 0x00,
            0x45, 0x00, 0x52, 0x00,
            0x00, 0x00, // Server Name
        ];
        DateTime systemTime = new(2013, 3, 14, 21, 28, 7, DateTimeKind.Utc);

        // Act
        var sut = new NegotiateResponse(buffer, true);

        // Assert
        sut.DialectIndex.Should().Be(8);
        sut.SecurityMode.Should().Be(SecurityMode.UserSecurityMode | SecurityMode.EncryptPasswords);
        sut.MaxMpxCount.Should().Be(50);
        sut.MaxNumberVcs.Should().Be(1);
        sut.MaxBufferSize.Should().Be(16644);
        sut.MaxRawSize.Should().Be(65536);
        sut.SessionKey.Should().Be(0x00001E19);
        sut.Capabilities.Should().Be(Capabilities.RawMode | Capabilities.Unicode | 
            Capabilities.LargeFiles | Capabilities.NTSMB | Capabilities.RpcRemoteApi |
            Capabilities.NTStatusCode | Capabilities.Level2Oplocks | Capabilities.LockAndRead |
            Capabilities.NTFind | Capabilities.DFS | Capabilities.InfoLevelPassthrough |
            Capabilities.LargeRead | Capabilities.LargeWrite | Capabilities.Unix  );
        sut.SystemTime.Should().Be(systemTime);
        sut.ServerTimeZone.Should().Be(0);
        sut.Challenge.Should().BeEmpty();
        sut.DomainName.Should().Be("DOMAIN");
        sut.ServerName.Should().Be("SERVER");
    }

    [Test]
    public void GetBytesCorrectly()
    {
        // Arrange
        var negotiateResponse = new NegotiateResponse
        {
            DialectIndex = 8,
            SecurityMode = SecurityMode.UserSecurityMode | SecurityMode.EncryptPasswords,
            MaxMpxCount = 50,
            MaxNumberVcs = 1,
            MaxBufferSize = 16644,
            MaxRawSize = 65536,
            SessionKey = 0x00001E19,
            Capabilities = Capabilities.RawMode | Capabilities.Unicode |
                Capabilities.LargeFiles | Capabilities.NTSMB | Capabilities.RpcRemoteApi |
                Capabilities.NTStatusCode | Capabilities.Level2Oplocks | Capabilities.LockAndRead |
                Capabilities.NTFind | Capabilities.DFS | Capabilities.InfoLevelPassthrough |
                Capabilities.LargeRead | Capabilities.LargeWrite | Capabilities.Unix,
            SystemTime = new(2013, 3, 14, 21, 28, 7, DateTimeKind.Utc),
            ServerTimeZone = 0,
            Challenge = [],
            DomainName = "DOMAIN",
            ServerName = "SERVER",
        };

        byte[] expectedBytes = [
            0x11, // Word Count
            0x08, 0x00, // Selected Dialect Index
            0x03, // Security Mode
            0x32, 0x00, // Max Mpx Count
            0x01, 0x00, // Max Number Vcs
            0x04, 0x41, 0x00, 0x00, // Max Buffer Size
            0x00, 0x00, 0x01, 0x00, // Max Raw Buffer
            0x19, 0x1e, 0x00, 0x00, // Session Key
            0xfd, 0xf3, 0x80, 0x00, // Capabilities
            0x80, 0x4d, 0x8e, 0xd1, 0xfa, 0x20, 0xce, 0x01, // System Time
            0x00, 0x00, // Server Time Zone
            0x00, // Challenge Length 
            0x1c, 0x00, // Byte Count
            0x44, 0x00, 0x4F, 0x00,
            0x4D, 0x00, 0x41, 0x00,
            0x49, 0x00, 0x4E, 0x00,
            0x00, 0x00, // Domain Name
            0x53, 0x00, 0x45, 0x00,
            0x52, 0x00, 0x56, 0x00,
            0x45, 0x00, 0x52, 0x00,
            0x00, 0x00, // Server Name
        ];


        // Act
        var resultBytes = negotiateResponse.GetBytes(true);

        // Assert
        resultBytes.Should().ContainInOrder(expectedBytes);
    }
}
