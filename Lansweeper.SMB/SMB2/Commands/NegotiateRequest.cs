using Lansweeper.Smb.SMB2.Commands.NegotiateContexts;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2.Commands;

/// <summary>
///     SMB2 NEGOTIATE Request
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       StructureSize           |           DialectCount        | 
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |       SecurityMode            |           Reserved            |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          Capabilities                         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   /                           ClientGuid                          /
///   |                                                               |
///   /                                                               /
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   | (NegotiateContextOffset,NegotiateContextCount,Reserved2)      |
///   /                                                               /
///   |                       /ClientStartTime                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                       Dialects (variable)                     |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                       Padding (variable)                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                  NegotiateContextList (variable)              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 
/// </summary>
public class NegotiateRequest : Smb2Command
{
    public const int DeclaredSize = 36;

    private ushort StructureSize { get; }
    // ushort DialectCount
    public SecurityMode SecurityMode { get; set; }
    public ushort Reserved { get; set; }
    /// <remarks> If the client does not implements the SMB 3.x dialect family, this field MUST be set to 0. </remarks>
    public Capabilities Capabilities { get; set; }

    public Guid ClientGuid { get; set; }

    /// <remarks> If Dialects does not contain SMB311 </remarks>
    public DateTime ClientStartTime { get; set; }
    public List<Smb2Dialect> Dialects { get; set; } = [];
    /// <remarks> If Dialects contains SMB311 </remarks>
    public List<NegotiateContext> NegotiateContextList { get; set; } = [];


    public NegotiateRequest() : base(Smb2CommandName.Negotiate)
    {
        StructureSize = DeclaredSize;
    }

    public NegotiateRequest(ReadOnlySpan<byte> buffer) : base(buffer, Smb2Dialect.Unknown)
    {
        ReadOnlySpan<byte> body = buffer[Smb2Header.Length..];
        StructureSize = LittleEndianReader.ReadUInt16(ref body);
        var dialectCount = LittleEndianReader.ReadUInt16(ref body);
        SecurityMode = (SecurityMode)LittleEndianReader.ReadUInt16(ref body);
        Reserved = LittleEndianReader.ReadUInt16(ref body);
        Capabilities = (Capabilities)LittleEndianReader.ReadUInt32(ref body);
        ClientGuid = LittleEndianReader.ReadGuid(ref body);

        // skip ClientStartTime or NegotiateContextOffset, NegotiateContextCount, Reserved2
        // the interpretation depends on the dialects
        ReadOnlySpan<byte> clientStartTimeOrNegotiationContext = body[..8];
        body = body[8..];
        var containsNegotiateContextList = false;
        for (var index = 0; index < dialectCount; index++)
        {
            var dialect = (Smb2Dialect)LittleEndianReader.ReadUInt16(ref body);
            Dialects.Add(dialect);

            if (dialect == Smb2Dialect.SMB311)
            {
                containsNegotiateContextList = true;
            }
        }

        // go back to the part we skipped
        if (containsNegotiateContextList)
        {
            var negotiateContextOffset = LittleEndianReader.ReadUInt32(ref clientStartTimeOrNegotiationContext);
            var negotiateContextCount = LittleEndianReader.ReadUInt16(ref clientStartTimeOrNegotiationContext);
            NegotiateContextList = NegotiateContext.ReadNegotiateContextList(buffer[(int)negotiateContextOffset..], negotiateContextCount);
        }
        else
        {
            ClientStartTime = LittleEndianReader.ReadFileTime(ref clientStartTimeOrNegotiationContext);
        }
    }


    public override int CommandLength
    {
        get
        {
            var containsSMB311Dialect = Dialects.Contains(Smb2Dialect.SMB311);
            if (containsSMB311Dialect && NegotiateContextList.Count > 0)
            {
                var paddingLength = (8 - (36 + Dialects.Count * 2) % 8) % 8;
                var negotiateContextListLength = NegotiateContext.GetNegotiateContextListLength(NegotiateContextList);
                return 36 + Dialects.Count * 2 + paddingLength + negotiateContextListLength;
            }

            return 36 + Dialects.Count * 2;
        }
    }

    public override void WriteCommandBytes(Span<byte> buffer)
    {
        LittleEndianWriter.WriteUInt16(ref buffer, StructureSize);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)Dialects.Count);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)SecurityMode);
        LittleEndianWriter.WriteUInt16(ref buffer, Reserved);
        LittleEndianWriter.WriteUInt32(ref buffer, (uint)Capabilities);
        LittleEndianWriter.WriteGuid(ref buffer, ClientGuid);

        bool containsSMB311Dialect = Dialects.Contains(Smb2Dialect.SMB311);
        int paddingLength = 0;

        if (containsSMB311Dialect)
        {
            paddingLength = (8 - (36 + Dialects.Count * 2) % 8) % 8;
            var negotiateContextOffset = (Smb2Header.Length + 36 + Dialects.Count * 2 + paddingLength);
            var negotiateContextCount = (ushort)NegotiateContextList.Count;
            LittleEndianWriter.WriteUInt32(ref buffer, (uint)negotiateContextOffset);
            LittleEndianWriter.WriteUInt16(ref buffer, negotiateContextCount);
            ByteWriter.WriteBytes(ref buffer, [0, 0]); // Reserved2
        }
        else
        {
            LittleEndianWriter.WriteInt64(ref buffer, ClientStartTime.ToFileTimeUtc());
        }

        foreach (var dialect in Dialects)
        {
            LittleEndianWriter.WriteUInt16(ref buffer, (ushort)dialect);
        }

        if (containsSMB311Dialect)
        {
            buffer[..paddingLength].Clear(); // write padding
            NegotiateContext.WriteNegotiateContextList(buffer[paddingLength..], NegotiateContextList);
        }

    }
}