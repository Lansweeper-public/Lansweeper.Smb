using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.3.7. SESSION KEEP ALIVE PACKET
/// 
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      TYPE     |     FLAGS     |            LENGTH             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class SessionKeepAlivePacket : SessionPacket
{
    public SessionKeepAlivePacket()
    {
        Type = SessionPacketTypeName.SessionKeepAlive;
    }

    public SessionKeepAlivePacket(ReadOnlySpan<byte> buffer) : base(buffer) { }

    public override int Length => HeaderLength;

    protected override byte[] CreateTrailer()
    {
        return [];
    }
}