namespace Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;

public enum DerEncodingTag : byte
{
    ByteArray = 0x04, // Octet String
    ObjectIdentifier = 0x06,
    Enum = 0x0A,
    GeneralString = 0x1B,
    Sequence = 0x30
}
