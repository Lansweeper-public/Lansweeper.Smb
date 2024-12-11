using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.3.6. SESSION MESSAGE PACKET
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      TYPE     |     FLAGS     |            LENGTH             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                                                               /
///   /                           USER_DATA                           /
///   /                                                               /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class SessionMessagePacket : SessionPacket
{
    public SessionMessagePacket(byte[] trailer)
    {
        Type = SessionPacketTypeName.SessionMessage;
        Trailer = trailer;
    }

    public SessionMessagePacket(ReadOnlySpan<byte> buffer) : base(buffer) { }

    protected override byte[] CreateTrailer()
    {
        // This method is not used in the current implementation
        // Trailer will always be set in the constructor
        throw new InvalidOperationException("This method should not be called");
    }
}