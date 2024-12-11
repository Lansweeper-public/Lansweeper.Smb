namespace Lansweeper.Smb.SMB2.Enums;

[Flags]
public enum SessionSetupFlags : byte
{
    None = 0x00,
    Binding = 0x01 // SMB2_SESSION_FLAG_BINDING
}