namespace Lansweeper.Smb.SMB1.Enums;

[Flags]
public enum SessionSetupAction : ushort
{
    None = 0x00,
    SetupGuest = 0x01, // SMB_SETUP_GUEST
    UseLanmanKey = 0x02 // SMB_SETUP_USE_LANMAN_KEY
}