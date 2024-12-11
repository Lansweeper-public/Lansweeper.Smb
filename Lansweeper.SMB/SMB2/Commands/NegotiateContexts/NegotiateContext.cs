using System.Buffers.Binary;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB2.Commands.NegotiateContexts;

/// <summary>
///     [MS-SMB2] 2.2.3.1 - NEGOTIATE_CONTEXT
///     
///                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         ContextType           |          DataLength           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                           Reserved                            |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                      Data (variable)                          |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 
/// </summary>
public class NegotiateContext
{
    public const int FixedLength = 8;

    public byte[] Data { get; set; } = [];
    public virtual NegotiateContextType ContextType { get; }
    // ushort DataLength
    public uint Reserved { get; set; }

    public NegotiateContext() { }

    public NegotiateContext(ReadOnlySpan<byte> buffer)
    {
        ContextType = (NegotiateContextType)LittleEndianReader.ReadUInt16(ref buffer);
        var dataLength = LittleEndianReader.ReadUInt16(ref buffer);
        Reserved = LittleEndianReader.ReadUInt32(ref buffer);
        Data = ByteReader.ReadBytes(ref buffer, dataLength);
    }

    public int Length => FixedLength + DataLength;

    public int PaddedLength
    {
        get
        {
            var paddingLength = (8 - DataLength % 8) % 8;
            return Length + paddingLength;
        }
    }

    public virtual int DataLength => Data.Length;

    public virtual void WriteData() { }

    public void WriteBytes(Span<byte> buffer)
    {
        WriteData();
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)ContextType);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)DataLength);
        LittleEndianWriter.WriteUInt32(ref buffer, Reserved);
        ByteWriter.WriteBytes(ref buffer, Data);
    }

    public static NegotiateContext ReadNegotiateContext(ReadOnlySpan<byte> buffer)
    {
        var contextType = (NegotiateContextType)BinaryPrimitives.ReadUInt16LittleEndian(buffer);
        return contextType switch
        {
            NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES => new PreAuthIntegrityCapabilities(buffer),
            NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES => new EncryptionCapabilities(buffer),
            _ => new NegotiateContext(buffer),
        };
    }

    public static List<NegotiateContext> ReadNegotiateContextList(ReadOnlySpan<byte> buffer, int count)
    {
        List<NegotiateContext> result = new(count);
        for (var index = 0; index < count; index++)
        {
            var context = ReadNegotiateContext(buffer);
            result.Add(context);
            // skip padding for the last context, could be longer than the buffer
            if (index < count - 1)
            {
                buffer = buffer[context.PaddedLength..];
            }
        }

        return result;
    }

    public static void WriteNegotiateContextList(Span<byte> buffer, List<NegotiateContext> negotiateContextList)
    {
        // Subsequent negotiate contexts MUST appear at the first 8-byte aligned offset following the previous negotiate context
        for (var index = 0; index < negotiateContextList.Count; index++)
        {
            var context = negotiateContextList[index];
            context.WriteBytes(buffer);
            // skip padding for the last context, could be longer than the buffer
            if (index < negotiateContextList.Count - 1)
            {
                buffer = buffer[context.PaddedLength..];
            }
        }
    }

    public static int GetNegotiateContextListLength(List<NegotiateContext> negotiateContextList)
    {
        var result = 0;
        for (var index = 0; index < negotiateContextList.Count; index++)
        {
            var context = negotiateContextList[index];
            if (index < negotiateContextList.Count - 1)
                result += context.PaddedLength;
            else
                result += context.Length;
        }

        return result;
    }
}