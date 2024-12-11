namespace Lansweeper.Smb.Netbios.Enums;

public enum OwnerNodeType : byte
{
    BNode = 0b00,
    PNode = 0b01,
    MNode = 0b10,
    Reserved = 0b11
}