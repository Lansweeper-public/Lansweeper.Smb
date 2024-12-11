using Lansweeper.Smb.Netbios.Enums;
using System;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.3.3. POSITIVE SESSION RESPONSE PACKET
/// </summary>
public class PositiveSessionResponsePacket : SessionPacket
{
    public PositiveSessionResponsePacket()
    {
        Type = SessionPacketTypeName.PositiveSessionResponse;
    }

    public PositiveSessionResponsePacket(ReadOnlySpan<byte> buffer) : base(buffer) { }

    public override int Length => HeaderLength;

    protected override byte[] CreateTrailer()
    {
        return []; // flyweight
    }
}