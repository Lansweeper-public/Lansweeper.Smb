using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Netbios;

namespace Lansweeper.SMB.Tests.Netbios;
internal class SessionMessagePacketShould
{
    [Test]
    public void InitializeProperties()
    {
        // Arrange
        var type = SessionPacketTypeName.SessionMessage;
        byte[] trailer = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        var trailerLength = trailer.Length;
        var buffer = new byte[4 + trailerLength];
        buffer[0] = (byte)type;
        buffer[1] = (byte)(trailerLength >> 16);
        buffer[2] = (byte)(trailerLength >> 8);
        buffer[3] = (byte)trailerLength;
        Array.Copy(trailer, 0, buffer, 4, trailerLength);

        // Act
        var sessionPacket = new SessionMessagePacket(buffer: buffer);

        // Assert
        sessionPacket.Type.Should().Be(type);
        sessionPacket.Trailer.Length.Should().Be(trailerLength);
        sessionPacket.Trailer.Should().Equal(trailer);
    }

    [Test]
    public void BeAbleToGetBytes()
    {
        byte[] trailer = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        byte[] expected = [0x00, 0x00, 0x00, 100, .. trailer];
        SessionMessagePacket packet = new(trailer: trailer);

        byte[] buffer = packet.GetBytes();
        buffer.Should().Equal(expected);
    }

    [Test]
    public void HaveCorrectLength()
    {
        SessionMessagePacket packet = new(trailer: []);
        packet.Length.Should().Be(4);
    }

}
