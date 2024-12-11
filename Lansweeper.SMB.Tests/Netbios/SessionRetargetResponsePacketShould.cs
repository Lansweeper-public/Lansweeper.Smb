using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Netbios;
using System.Buffers.Binary;

namespace Lansweeper.SMB.Tests.Netbios;
internal class SessionRetargetResponsePacketShould
{
    [Test]
    public void InitializeProperties()
    {
        // Arrange
        var type = SessionPacketTypeName.RetargetSessionResponse;
        byte[] ipAsBytes = [10, 12, 0, 1];
        uint ipAsUInt = BinaryPrimitives.ReadUInt32BigEndian(ipAsBytes);
        byte[] portAsBytes = [0x03, 0x7C];
        ushort portAsUShort = BinaryPrimitives.ReadUInt16BigEndian(portAsBytes);
        byte[] trailer = [.. ipAsBytes, .. portAsBytes];
        var trailerLength = trailer.Length;
        var buffer = new byte[4 + trailerLength];
        buffer[0] = (byte)type;
        buffer[1] = (byte)(trailerLength >> 16);
        buffer[2] = (byte)(trailerLength >> 8);
        buffer[3] = (byte)trailerLength;
        Array.Copy(trailer, 0, buffer, 4, trailerLength);

        // Act
        var sessionPacket = new SessionRetargetResponsePacket(buffer);

        // Assert
        sessionPacket.Type.Should().Be(type);
        sessionPacket.Trailer.Length.Should().Be(trailerLength);
        sessionPacket.Trailer.Should().Equal(trailer);
        sessionPacket.IPAddress.Should().Be(ipAsUInt);
        sessionPacket.Port.Should().Be(portAsUShort);
    }

    [Test]
    public void BeAbleToGetBytes()
    {
        byte[] ipAsBytes = [10, 12, 0, 1];
        uint ipAsUInt = BinaryPrimitives.ReadUInt32BigEndian(ipAsBytes);
        byte[] portAsBytes = [0x03, 0x7C];
        ushort portAsUShort = BinaryPrimitives.ReadUInt16BigEndian(portAsBytes);
        byte trailerLength = 4 + 2; // 1 byte
        byte[] expected = [0x84, 0x00, 0x00, trailerLength, .. ipAsBytes, .. portAsBytes];
        SessionRetargetResponsePacket packet = new(ipAsUInt, portAsUShort);

        byte[] buffer = packet.GetBytes();
        buffer.Should().Equal(expected);
    }

    [Test]
    public void HaveCorrectLength()
    {
        byte[] ipAsBytes = [10, 12, 0, 1];
        uint ipAsUInt = BinaryPrimitives.ReadUInt32BigEndian(ipAsBytes);
        byte[] portAsBytes = [0x03, 0x7C];
        ushort portAsUShort = BinaryPrimitives.ReadUInt16BigEndian(portAsBytes);

        SessionRetargetResponsePacket packet = new(ipAsUInt, portAsUShort);
        packet.Length.Should().Be(4 + 4 + 2);
    }
}