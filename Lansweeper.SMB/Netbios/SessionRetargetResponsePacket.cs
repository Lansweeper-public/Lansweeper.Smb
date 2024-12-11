using Lansweeper.Smb.Netbios.Enums;
using System.Buffers.Binary;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.3.5. SESSION RETARGET RESPONSE PACKET
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      TYPE     |     FLAGS     |            LENGTH             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                      RETARGET_IP_ADDRESS                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |           PORT                |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </summary>
public class SessionRetargetResponsePacket : SessionPacket
{
    public uint IPAddress { get; }
    public ushort Port { get; }

    public SessionRetargetResponsePacket(uint ipAddress, ushort port)
    {
        Type = SessionPacketTypeName.RetargetSessionResponse;
        IPAddress = ipAddress;
        Port = port;
    }

    public SessionRetargetResponsePacket(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        IPAddress = BinaryPrimitives.ReadUInt32BigEndian(buffer[HeaderLength..]);
        Port = BinaryPrimitives.ReadUInt16BigEndian(buffer[(HeaderLength + 4)..]);
    }

    public override int Length => HeaderLength + 6;

    protected override byte[] CreateTrailer()
    {
        byte[] trailer = new byte[6];
        Span<byte> trailerAsSpan = trailer;
        BinaryPrimitives.WriteUInt32BigEndian(trailerAsSpan, IPAddress);
        BinaryPrimitives.WriteUInt16BigEndian(trailerAsSpan[4..], Port);
        return trailer;
    }
}