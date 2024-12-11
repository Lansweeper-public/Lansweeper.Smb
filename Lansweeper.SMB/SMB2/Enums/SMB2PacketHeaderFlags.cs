namespace Lansweeper.Smb.SMB2.Enums;

[Flags]
public enum Smb2PacketHeaderFlags : uint
{
    ServerToRedir = 0x0000001, // SMB2_FLAGS_SERVER_TO_REDIR
    AsyncCommand = 0x0000002, // SMB2_FLAGS_ASYNC_COMMAND
    RelatedOperations = 0x0000004, // SMB2_FLAGS_RELATED_OPERATIONS
    Signed = 0x0000008, // SMB2_FLAGS_SIGNED
    PriorityMask = 0x00000070, // SMB2_FLAGS_PRIORITY_MASK
    Priority1 = 0x0000010,
    Priority2 = 0x0000020,
    Priority3 = 0x0000030,
    Priority4 = 0x0000040,
    Priority5 = 0x0000050,
    Priority6 = 0x0000060,
    Priority7 = 0x0000070,
    DfsOperations = 0x10000000, // SMB2_FLAGS_DFS_OPERATIONS
    ReplayOperation = 0x20000000, // SMB2_FLAGS_REPLAY_OPERATION
}