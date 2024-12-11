using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Netbios;

namespace Lansweeper.SMB.Tests.Netbios;

internal class PositiveSessionResponsePacketShould
{
    [Test]
    public void InitializeProperties()
    {
        // Arrange
        var type = SessionPacketTypeName.PositiveSessionResponse;
        var trailer = Array.Empty<byte>();
        var trailerLength = trailer.Length;
        var buffer = new byte[4 + trailerLength];
        buffer[0] = (byte)type;
        buffer[1] = (byte)(trailerLength >> 16);
        buffer[2] = (byte)(trailerLength >> 8);
        buffer[3] = (byte)trailerLength;

        // Act
        var sessionPacket = new PositiveSessionResponsePacket(buffer);

        // Assert
        sessionPacket.Type.Should().Be(type);
        sessionPacket.Trailer.Length.Should().Be(trailerLength);
        sessionPacket.Trailer.Should().Equal(trailer);
    }

    [Test]
    public void BeAbleToGetBytes()
    {
        byte[] expected = [0x82, 0x00, 0x00, 0x00];
        PositiveSessionResponsePacket packet = new();

        byte[] buffer = packet.GetBytes();
        buffer.Should().Equal(expected);
    }

    [Test]
    public void HaveCorrectLength()
    {
        PositiveSessionResponsePacket packet = new();
        packet.Length.Should().Be(4);
    }

}
