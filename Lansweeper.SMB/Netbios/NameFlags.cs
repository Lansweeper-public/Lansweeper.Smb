using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///                                              1   1   1   1   1   1
///     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
///   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///   | G |  ONT  |DRG|CNF|ACT|PRM|          RESERVED                 |
///   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// </summary>
public readonly struct NameFlags
{
    /// <summary> Group Name Flag </summary>
    public bool IsGroupName { get; }
    public bool IsUnique => !IsGroupName;
    public OwnerNodeType Type { get; }
    /// <summary> Deregister Flag </summary>
    public bool IsBeingDeleted { get; }
    /// <summary> Deregister Flag </summary>
    public bool IsInConflict { get; }
    /// <summary> Active Name Flag, should always be true </summary>
    public bool IsActiveName { get; }
    /// <summary> Permanent Name Flag </summary>
    public bool IsPermanent { get; }


    public NameFlags(ReadOnlySpan<byte> buffer)
    {
        IsGroupName = (buffer[0] & 0x80) > 0;
        Type = (OwnerNodeType)((buffer[0] >> 5) & 0x3);
        IsBeingDeleted = (buffer[0] & 0x10) > 0;
        IsInConflict = (buffer[0] & 0x08) > 0;
        IsActiveName = (buffer[0] & 0x04) > 0;
        IsPermanent = (buffer[0] & 0x02) > 0;
    }

    public NameFlags(bool isGroupName, OwnerNodeType type, bool isBeingDeleted, bool isInConflict, bool isActiveName, bool isPermanent)
    {
        IsGroupName = isGroupName;
        Type = type;
        IsBeingDeleted = isBeingDeleted;
        IsInConflict = isInConflict;
        IsActiveName = isActiveName;
        IsPermanent = isPermanent;
    }

    public void WriteBytes(Stream stream)
    {
        Span<byte> bytes = stackalloc byte[2];
        bytes[0] = (byte)(
            (IsGroupName ? 0x80 : 0)
            | ((byte)Type << 5)
            | (IsBeingDeleted ? 0x10 : 0)
            | (IsInConflict ? 0x08 : 0)
            | (IsActiveName ? 0x04 : 0)
            | (IsPermanent ? 0x02 : 0)
            );
        bytes[1] = 0; // always 0

        stream.Write(bytes);
    }

}