using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.3.2. SESSION REQUEST PACKET
///     
///                          1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      TYPE     |     FLAGS     |            LENGTH             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   /                          CALLED NAME  (18 bytes)              /
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   /                          CALLING NAME (18 bytes)              /
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class SessionRequestPacket : SessionPacket
{
    public string CalledName { get; private set; }
    public string CallingName { get; }

    public SessionRequestPacket(string calledName, string callingName)
    {
        Type = SessionPacketTypeName.SessionRequest;
        CalledName = calledName;
        CallingName = callingName;
    }

    public SessionRequestPacket(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        ReadOnlySpan<byte> trailer = Trailer;
        CalledName = NetBiosUtils.DecodeName(ref trailer);
        CallingName = NetBiosUtils.DecodeName(ref trailer);
    }

    protected override byte[] CreateTrailer()
    {
        var calledName = NetBiosUtils.EncodeName(CalledName, string.Empty);
        var callingName = NetBiosUtils.EncodeName(CallingName, string.Empty);
        return [.. calledName, .. callingName];
    }
}