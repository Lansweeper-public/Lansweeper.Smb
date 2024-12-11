using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;

namespace Lansweeper.SMB.Tests.SMB1.Commands;

public class NegotiateResponseExtendedShould
{
    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // Arrange
        byte[] securityBlob = [ 0x60, 0x28, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0,
            0x1e, 0x30, 0x1c, 0xa0, 0x0e, 0x30, 0x0c, 0x06,
            0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37,
            0x02, 0x02, 0x0a, 0xa3, 0x0a, 0x30, 0x08, 0xa0,
            0x06, 0x1b, 0x04, 0x4e, 0x4f, 0x4e, 0x45 ];
        DateTime systemTime = new(2013, 3, 14, 21, 28, 7, DateTimeKind.Utc);

        byte[] buffer = [
            0x11, // Word Count
            0x08, 0x00, // Selected Dialect Index
            0x03, // Security Mode
            0x32, 0x00, // Max Mpx Count
            0x01, 0x00, // Max Number Vcs
            0x04, 0x41, 0x00, 0x00, // Max Buffer Size
            0x00, 0x00, 0x01, 0x00, // Max Raw Buffer
            0x19, 0x1e, 0x00, 0x00, // Session Key
            0xfd, 0xf3, 0x80, 0x80, // Capabilities
            0x80, 0x4d, 0x8e, 0xd1, 0xfa, 0x20, 0xce, 0x01, // System Time
            0x00, 0x00, // Server Time Zone
            0x00, // Challenge Length 
            0x3a, 0x00, // Byte Count
            0x68, 0x6d, 0x6e, 0x68, 0x64, 0x2d, 0x74, 0x69, 0x31, 0x6b, 0x6c, 0x73, 0x00, 0x00, 0x00, 0x00, // Server Guid
            ..securityBlob
        ];

        // Act
        var sut = new NegotiateResponseExtended(buffer);

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
            Capabilities.LargeRead | Capabilities.LargeWrite | Capabilities.Unix | Capabilities.ExtendedSecurity);
        sut.SystemTime.Should().Be(systemTime);
        sut.ServerTimeZone.Should().Be(0);
        sut.ServerGuid.Should().Be(Guid.Parse("686d6e68-642d-7469-316b-6c7300000000"));
        sut.SecurityBlob.Should().Equal(securityBlob);
    }

    [Test]
    public void GetBytesCorrectly()
    {
        // Arrange
        byte[] securityBlob = [ 0x60, 0x28, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0,
            0x1e, 0x30, 0x1c, 0xa0, 0x0e, 0x30, 0x0c, 0x06,
            0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37,
            0x02, 0x02, 0x0a, 0xa3, 0x0a, 0x30, 0x08, 0xa0,
            0x06, 0x1b, 0x04, 0x4e, 0x4f, 0x4e, 0x45 ];

        NegotiateResponseExtended sut = new()
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
                Capabilities.LargeRead | Capabilities.LargeWrite | Capabilities.Unix | Capabilities.ExtendedSecurity,
            SystemTime = new(2013, 3, 14, 21, 28, 7, DateTimeKind.Utc),
            ServerTimeZone = 0,
            ServerGuid = Guid.Parse("686d6e68-642d-7469-316b-6c7300000000"),
            SecurityBlob = securityBlob,
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
            0xfd, 0xf3, 0x80, 0x80, // Capabilities
            0x80, 0x4d, 0x8e, 0xd1, 0xfa, 0x20, 0xce, 0x01, // System Time
            0x00, 0x00, // Server Time Zone
            0x00, // Challenge Length 
            0x3a, 0x00, // Byte Count
            0x68, 0x6d, 0x6e, 0x68, 0x64, 0x2d, 0x74, 0x69, 0x31, 0x6b, 0x6c, 0x73, 0x00, 0x00, 0x00, 0x00, // Server Guid
            ..securityBlob,
        ];


        // Act
        var actualBytes = sut.GetBytes(false);

        // Assert
        actualBytes.Should().Equal(expectedBytes);
    }
}
