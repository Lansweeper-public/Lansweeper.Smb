using Lansweeper.Smb.Netbios.Enums;
using System;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.3.4. NEGATIVE SESSION RESPONSE PACKET
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      TYPE     |     FLAGS     |            LENGTH             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |   ERROR_CODE  |
///   +-+-+-+-+-+-+-+-+
/// </summary>
public class NegativeSessionResponsePacket : SessionPacket
{
    public ErrorCodeType ErrorCode { get; }

    /// <inheritdoc/>
    public NegativeSessionResponsePacket(ErrorCodeType errorCode)
    {
        Type = SessionPacketTypeName.NegativeSessionResponse;
        ErrorCode = errorCode;
    }

    public NegativeSessionResponsePacket(ReadOnlySpan<byte> buffer) : base(buffer)
    {
        ErrorCode = (ErrorCodeType)Trailer[0];
    }

    public override int Length => HeaderLength + 1;

    protected override byte[] CreateTrailer()
    {
        return [(byte)ErrorCode];
    }

    public enum ErrorCodeType : byte
    {
        NotListeningOnCalledName = 0x80,
        NotListeningForCallingName = 0x81,
        CalledNameNotPresent = 0x82,
        CalledNamePresentInsufficientResources = 0x83,
        Unspecified = 0x8F,
    }
}