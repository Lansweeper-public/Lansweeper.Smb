using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Netbios;

/// <summary>
/// 
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |               UNIT_ID(Unique unit ID)                         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       UNIT_ID,continued       |    JUMPERS    |  TEST_RESULT  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       VERSION_NUMBER          |      PERIOD_OF_STATISTICS     |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       NUMBER_OF_CRCs          |     NUMBER_ALIGNMENT_ERRORS   |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       NUMBER_OF_COLLISIONS    |        NUMBER_SEND_ABORTS     |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                       NUMBER_GOOD_SENDS                       |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                      NUMBER_GOOD_RECEIVES                     |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       NUMBER_RETRANSMITS      | NUMBER_NO_RESOURCE_CONDITIONS |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  NUMBER_FREE_COMMAND_BLOCKS   |  TOTAL_NUMBER_COMMAND_BLOCKS  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |MAX_TOTAL_NUMBER_COMMAND_BLOCKS|    NUMBER_PENDING_SESSIONS    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  MAX_NUMBER_PENDING_SESSIONS  |  MAX_TOTAL_SESSIONS_POSSIBLE  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |   SESSION_DATA_PACKET_SIZE    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// </summary>
public class NodeStatistics
{
    public const int Length = 46;
    public byte Jumpers { get; }
    public ushort MaxNumberOfPendingSessions { get; }
    public ushort MaxTotalNumberOfCommandBlocks { get; }
    public ushort MaxTotalsSessionsPossible { get; }
    public ushort NumberOfAlignmentErrors { get; }
    public ushort NumberOfCollisions { get; }
    public ushort NumberOfCRCs { get; }
    public ushort NumberOfFreeCommandBlocks { get; }
    public uint NumberOfGoodReceives { get; }
    public uint NumberOfGoodSends { get; }
    public ushort NumberOfNoResourceConditions { get; }
    public ushort NumberOfPendingSessions { get; }
    public ushort NumberOfRetransmits { get; }
    public ushort NumberOfSendAborts { get; }
    public ushort PeriodOfStatistics { get; }
    public ushort SessionDataPacketSize { get; }
    public byte TestResult { get; }
    public ushort TotalNumberOfCommandBlocks { get; }
    public byte[] UnitID { get; } // MAC address, 6 bytes
    public ushort VersionNumber { get; }

    public NodeStatistics()
    {
        UnitID = new byte[6];
    }

    public NodeStatistics(ReadOnlySpan<byte> buffer)
    {
        UnitID = ByteReader.ReadBytes(ref buffer, 6);
        Jumpers = ByteReader.ReadByte(ref buffer);
        TestResult = ByteReader.ReadByte(ref buffer);
        VersionNumber = BigEndianReader.ReadUInt16(ref buffer);
        PeriodOfStatistics = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfCRCs = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfAlignmentErrors = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfCollisions = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfSendAborts = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfGoodSends = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfGoodReceives = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfRetransmits = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfNoResourceConditions = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfFreeCommandBlocks = BigEndianReader.ReadUInt16(ref buffer);
        TotalNumberOfCommandBlocks = BigEndianReader.ReadUInt16(ref buffer);
        MaxTotalNumberOfCommandBlocks = BigEndianReader.ReadUInt16(ref buffer);
        NumberOfPendingSessions = BigEndianReader.ReadUInt16(ref buffer);
        MaxNumberOfPendingSessions = BigEndianReader.ReadUInt16(ref buffer);
        MaxTotalsSessionsPossible = BigEndianReader.ReadUInt16(ref buffer);
        SessionDataPacketSize = BigEndianReader.ReadUInt16(ref buffer);
    }

    public void WriteBytes(Span<byte> buffer)
    {
        ByteWriter.WriteBytes(ref buffer, UnitID.AsSpan(6));
        ByteWriter.WriteByte(ref buffer, Jumpers);
        ByteWriter.WriteByte(ref buffer, TestResult);
        BigEndianWriter.WriteUInt16(ref buffer, VersionNumber);
        BigEndianWriter.WriteUInt16(ref buffer, PeriodOfStatistics);
        BigEndianWriter.WriteUInt16(ref buffer, NumberOfCRCs);
        BigEndianWriter.WriteUInt16(ref buffer, NumberOfAlignmentErrors);
        BigEndianWriter.WriteUInt16(ref buffer, NumberOfCollisions);
        BigEndianWriter.WriteUInt16(ref buffer, NumberOfSendAborts);
        BigEndianWriter.WriteUInt32(ref buffer, NumberOfGoodSends);
        BigEndianWriter.WriteUInt32(ref buffer, NumberOfGoodReceives);
        BigEndianWriter.WriteUInt16(ref buffer, NumberOfRetransmits);
        BigEndianWriter.WriteUInt16(ref buffer, NumberOfNoResourceConditions);
        BigEndianWriter.WriteUInt16(ref buffer, NumberOfFreeCommandBlocks);
        BigEndianWriter.WriteUInt16(ref buffer, TotalNumberOfCommandBlocks);
        BigEndianWriter.WriteUInt16(ref buffer, MaxTotalNumberOfCommandBlocks);
        BigEndianWriter.WriteUInt16(ref buffer, NumberOfPendingSessions);
        BigEndianWriter.WriteUInt16(ref buffer, MaxNumberOfPendingSessions);
        BigEndianWriter.WriteUInt16(ref buffer, MaxTotalsSessionsPossible);
        BigEndianWriter.WriteUInt16(ref buffer, SessionDataPacketSize);
    }


    public byte[] GetBytes()
    {
        var buffer = new byte[Length];
        WriteBytes(buffer);
        return buffer;
    }
}