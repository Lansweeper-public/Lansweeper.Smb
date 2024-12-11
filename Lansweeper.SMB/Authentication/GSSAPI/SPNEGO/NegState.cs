namespace Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;

public enum NegState : byte
{
    AcceptCompleted = 0x00,
    AcceptIncomplete = 0x01,
    Reject = 0x02,
    RequestMic = 0x03
}
