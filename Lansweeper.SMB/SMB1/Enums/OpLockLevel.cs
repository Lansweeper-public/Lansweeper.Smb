namespace Lansweeper.Smb.SMB1.Enums;

public enum OpLockLevel : byte
{
    NoOpLockGranted = 0x00,
    ExclusiveOpLockGranted = 0x01,
    BatchOpLockGranted = 0x02,
    Level2OpLockGranted = 0x03
}