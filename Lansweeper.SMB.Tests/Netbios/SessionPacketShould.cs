using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Netbios;

namespace Lansweeper.SMB.Tests.Netbios;
internal class SessionPacketShould
{
    private class TestSessionPacket(ReadOnlySpan<byte> buffer) : SessionPacket(buffer)
    {
        protected override byte[] CreateTrailer() => []; // Not used in the current implementation
    }

    [Test]
    public void InitializeProperties()
    {
        // Arrange
        var type = SessionPacketTypeName.SessionMessage;
        byte[] trailer = [0x01, 0x02, 0x03];
        var trailerLength = trailer.Length;
        var buffer = new byte[4 + trailerLength];
        buffer[0] = (byte)type;
        buffer[1] = (byte)(trailerLength >> 16);
        buffer[2] = (byte)(trailerLength >> 8);
        buffer[3] = (byte)trailerLength;
        Array.Copy(trailer, 0, buffer, 4, trailerLength);

        // Act
        var sessionPacket = new TestSessionPacket(buffer);

        // Assert
        sessionPacket.Type.Should().Be(type);
        sessionPacket.Trailer.Length.Should().Be(trailerLength);
        sessionPacket.Trailer.Should().Equal(trailer);
    }

    [Test]
    public void ReturnCorrectPacketForGetSessionPacket()
    {
        // Arrange
        var type = SessionPacketTypeName.SessionMessage;
        byte[] trailer = [0x01, 0x02, 0x03];
        var trailerLength = trailer.Length;
        var buffer = new byte[4 + trailerLength];
        buffer[0] = (byte)type;
        buffer[1] = (byte)(trailerLength >> 16);
        buffer[2] = (byte)(trailerLength >> 8);
        buffer[3] = (byte)trailerLength;
        Array.Copy(trailer, 0, buffer, 4, trailerLength);

        // Act
        var result = SessionPacket.GetSessionPacket(buffer);

        // Assert
        result.Type.Should().Be(type);
        result.Trailer.Length.Should().Be(trailerLength);
        result.Trailer.Should().Equal(trailer);
    }


}
