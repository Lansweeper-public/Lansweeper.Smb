using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Netbios;
using ErrorCode = Lansweeper.Smb.Netbios.NegativeSessionResponsePacket.ErrorCodeType;

namespace Lansweeper.SMB.Tests.Netbios;
internal class NegativeSessionResponsePacketShould
{
    [Test]
    public void InitializeProperties()
    {
        // Arrange
        var type = SessionPacketTypeName.NegativeSessionResponse;
        var trailer = new byte[] { 0x82 }; // 82 = Called name not present
        var trailerLength = trailer.Length;
        var buffer = new byte[4 + trailerLength];
        buffer[0] = (byte)type;
        buffer[1] = (byte)(trailerLength >> 16);
        buffer[2] = (byte)(trailerLength >> 8);
        buffer[3] = (byte)trailerLength;
        Array.Copy(trailer, 0, buffer, 4, trailerLength);

        // Act
        var sessionPacket = new NegativeSessionResponsePacket(buffer);

        // Assert
        sessionPacket.Type.Should().Be(type);
        sessionPacket.Trailer.Length.Should().Be(trailerLength);
        sessionPacket.Trailer.Should().Equal(trailer);
        sessionPacket.ErrorCode.Should().Be(ErrorCode.CalledNameNotPresent);
    }

    [Test]
    public void BeAbleToGetBytes()
    {
        byte[] expected = [0x83, 0x00, 0x00, 0x01, 0x82];
        NegativeSessionResponsePacket packet = new(ErrorCode.CalledNameNotPresent);

        byte[] buffer = packet.GetBytes();
        buffer.Should().Equal(expected);
    }

    [Test]
    public void HaveCorrectLength()
    {
        NegativeSessionResponsePacket packet = new(ErrorCode.CalledNameNotPresent);
        packet.Length.Should().Be(5);
    }
}