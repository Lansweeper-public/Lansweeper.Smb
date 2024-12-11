using Lansweeper.Smb.Enums;
using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1;

/// <summary>
/// 2.2.3.1 The SMB Header
/// 
/// SMB_Header
/// {
///   UCHAR Protocol[4]; // must be 0xFF, 'S', 'M', 'B'
///   UCHAR Command;
///   SMB_ERROR Status;
///   UCHAR Flags;
///   USHORT Flags2;
///   USHORT PIDHigh;
///   UCHAR SecurityFeatures[8];
///   USHORT Reserved;
///   USHORT TID;
///   USHORT PIDLow;
///   USHORT UID;
///   USHORT MID;
/// }
/// </summary>
public class Smb1Header
{
    public const int Length = 32;

    public static readonly byte[] ProtocolSignature = [0xFF, 0x53, 0x4D, 0x42];
    private byte[] Protocol { get; } // byte[4], 0xFF followed by "SMB"
    public CommandName Command { get; set; }
    public NTStatus Status { get; set; }
    public HeaderFlags Flags { get; set; }
    public HeaderFlags2 Flags2 { get; set; }
    //ushort PIDHigh
    public ulong SecurityFeatures { get; set; }
    // ushort Reserved
    /// <summary> Tree ID </summary>
    public ushort TID { get; set; }
    // ushort PIDLow
    /// <summary> Process ID, combined from PIDHigh and PIDLow </summary>
    public uint PID { get; set; }
    /// <summary> User ID </summary>
    public ushort UID { get; set; }
    /// <summary>Multiplex ID </summary>
    public ushort MID { get; set; }


    public Smb1Header()
    {
        Protocol = ProtocolSignature;
    }

    public Smb1Header(ReadOnlySpan<byte> buffer)
    {
        Protocol = ByteReader.ReadBytes(ref buffer, 4);
        Command = (CommandName)ByteReader.ReadByte(ref buffer);
        Status = (NTStatus)LittleEndianReader.ReadUInt32(ref buffer);
        Flags = (HeaderFlags)ByteReader.ReadByte(ref buffer);
        Flags2 = (HeaderFlags2)LittleEndianReader.ReadUInt16(ref buffer);
        var PIDHigh = LittleEndianReader.ReadUInt16(ref buffer);
        SecurityFeatures = LittleEndianReader.ReadUInt64(ref buffer);
        buffer = buffer.Slice(2); // skip Reserved
        TID = LittleEndianReader.ReadUInt16(ref buffer);
        var PIDLow = LittleEndianReader.ReadUInt16(ref buffer);
        UID = LittleEndianReader.ReadUInt16(ref buffer);
        MID = LittleEndianReader.ReadUInt16(ref buffer);

        PID = (uint)((PIDHigh << 16) | PIDLow);
    }

    public bool ReplyFlag => (Flags & HeaderFlags.Reply) > 0;

    /// <summary>
    ///     SMB_FLAGS2_EXTENDED_SECURITY
    /// </summary>
    public bool ExtendedSecurityFlag
    {
        get => (Flags2 & HeaderFlags2.ExtendedSecurity) > 0;
        set
        {
            if (value)
                Flags2 |= HeaderFlags2.ExtendedSecurity;
            else
                Flags2 &= ~HeaderFlags2.ExtendedSecurity;
        }
    }

    public bool UnicodeFlag
    {
        get => (Flags2 & HeaderFlags2.Unicode) > 0;
        set
        {
            if (value)
                Flags2 |= HeaderFlags2.Unicode;
            else
                Flags2 &= ~HeaderFlags2.Unicode;
        }
    }

    public void WriteBytes(Span<byte> buffer)
    {
        var PIDHigh = (ushort)(PID >> 16);
        var PIDLow = (ushort)(PID & 0xFFFF);

        ByteWriter.WriteBytes(ref buffer, Protocol);
        ByteWriter.WriteByte(ref buffer, (byte)Command);
        LittleEndianWriter.WriteUInt32(ref buffer, (uint)Status);
        ByteWriter.WriteByte(ref buffer, (byte)Flags);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)Flags2);
        LittleEndianWriter.WriteUInt16(ref buffer, PIDHigh);
        LittleEndianWriter.WriteUInt64(ref buffer, SecurityFeatures);
        ByteWriter.WriteBytes(ref buffer, [0x00, 0x00]); // Reserved
        LittleEndianWriter.WriteUInt16(ref buffer, TID);
        LittleEndianWriter.WriteUInt16(ref buffer, PIDLow);
        LittleEndianWriter.WriteUInt16(ref buffer, UID);
        LittleEndianWriter.WriteUInt16(ref buffer, MID);
    }


    public byte[] GetBytes()
    {
        var buffer = new byte[Length];
        WriteBytes(buffer);
        return buffer;
    }

    public static bool IsValidSMB1Header(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 4) return false;

        return buffer[0] == ProtocolSignature[0] && // fast check
               buffer[1] == ProtocolSignature[1] &&
               buffer[2] == ProtocolSignature[2] &&
               buffer[3] == ProtocolSignature[3];
    }

}