namespace Lansweeper.Smb.Netbios.Enums;

/// <summary>
///     [RFC 1002] 4.2.1.1. HEADER
/// </summary>
public enum SessionPacketTypeName : byte
{
    SessionMessage = 0x00,
    SessionRequest = 0x81,
    PositiveSessionResponse = 0x82,
    NegativeSessionResponse = 0x83,
    RetargetSessionResponse = 0x84,
    SessionKeepAlive = 0x85
}