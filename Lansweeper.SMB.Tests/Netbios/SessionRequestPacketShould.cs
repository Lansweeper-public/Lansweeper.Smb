using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.SMB.Tests.Netbios;

internal class SessionRequestPacketShould
{
    [Test]
    public void InitializeProperties()
    {
        // Arrange
        var type = SessionPacketTypeName.SessionRequest;
        var calledName = "CALLED_NAME     "; // 16 bytes
        var callingName = "CALLING_NAME    ";
        var encodedCalledName = NetBiosUtils.EncodeName(calledName, string.Empty); // 18 bytes
        var encodedCallingName = NetBiosUtils.EncodeName(callingName, string.Empty);
        byte[] trailer = [..encodedCalledName, ..encodedCallingName];
        var trailerLength = trailer.Length;

        var buffer = new byte[4 + trailerLength];
        buffer[0] = (byte)type;
        buffer[1] = (byte)(trailerLength >> 16);
        buffer[2] = (byte)(trailerLength >> 8);
        buffer[3] = (byte)trailerLength;
        Array.Copy(trailer, 0, buffer, 4, trailerLength);

        // Act
        var packet = new SessionRequestPacket(buffer);

        // Assert
        packet.CalledName.Should().Be(calledName);
        packet.CallingName.Should().Be(callingName);
    }

    [Test]
    public void BeAbleToGetBytes()
    {
        var calledName = "CALLED_NAME     "; // 16 bytes
        var callingName = "CALLING_NAME    ";
        var encodedCalledName = NetBiosUtils.EncodeName(calledName, string.Empty); // 18 bytes
        var encodedCallingName = NetBiosUtils.EncodeName(callingName, string.Empty);
        byte[] trailer = [.. encodedCalledName, .. encodedCallingName];
        byte[] expected = [0x81, 0x00, 0x00, (byte)trailer.Length, .. trailer];
        SessionRequestPacket packet = new(calledName, callingName);

        byte[] buffer = packet.GetBytes();
        buffer.Should().Equal(expected);
    }

    [Test]
    public void HaveCorrectLength()
    {
        var calledName = "CALLED_NAME     "; // 16 bytes
        var callingName = "CALLING_NAME    ";
        var encodedCalledName = NetBiosUtils.EncodeName(calledName, string.Empty); // 18 bytes
        var encodedCallingName = NetBiosUtils.EncodeName(callingName, string.Empty);
        byte[] trailer = [.. encodedCalledName, .. encodedCallingName];
        SessionRequestPacket packet = new(calledName, callingName);

        packet.Length.Should().Be(trailer.Length + SessionPacket.HeaderLength);
    }
}
