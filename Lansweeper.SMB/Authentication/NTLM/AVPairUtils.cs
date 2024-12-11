using System.Buffers.Binary;
using System.Text;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.NTLM;

public static class AVPairUtils
{
    public static KeyValuePairList<AVPairKey, byte[]> GetAVPairSequence(string domainName, string computerName)
    {
        KeyValuePairList<AVPairKey, byte[]> pairs = new()
        {
            { AVPairKey.NbDomainName, Encoding.Unicode.GetBytes(domainName) },
            { AVPairKey.NbComputerName, Encoding.Unicode.GetBytes(computerName) }
        };
        return pairs;
    }

    public static byte[] GetAVPairSequenceBytes(KeyValuePairList<AVPairKey, byte[]> pairs)
    {
        var length = GetAVPairSequenceLength(pairs);
        var result = new byte[length];
        var span = result.AsSpan();
        WriteAVPairSequence(ref span, pairs);
        return result;
    }

    public static int GetAVPairSequenceLength(KeyValuePairList<AVPairKey, byte[]> pairs)
    {
        var length = 0;
        foreach (var pair in pairs)
        {
            length += 4 + pair.Value.Length;
        }

        return length + 4; // extra 4 for EOL
    }

    public static void WriteAVPairSequence(ref Span<byte> buffer, KeyValuePairList<AVPairKey, byte[]> pairs)
    {
        foreach (var pair in pairs)
        {
            WriteAVPair(ref buffer, pair.Key, pair.Value);
        }

        // always end with EOL
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)AVPairKey.EOL);
        LittleEndianWriter.WriteUInt16(ref buffer, 0);
    }

    private static void WriteAVPair(ref Span<byte> buffer, AVPairKey key, ReadOnlySpan<byte> value)
    {
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)key);
        LittleEndianWriter.WriteUInt16(ref buffer, (ushort)value.Length);
        ByteWriter.WriteBytes(ref buffer, value);
    }

    public static KeyValuePairList<AVPairKey, byte[]> ReadAVPairSequence(ReadOnlySpan<byte> buffer)
    {
        var result = new KeyValuePairList<AVPairKey, byte[]>();
        var key = (AVPairKey)BinaryPrimitives.ReadUInt16LittleEndian(buffer);
        while (key != AVPairKey.EOL)
        {
            var pair = ReadAVPair(ref buffer);
            result.Add(pair);
            key = (AVPairKey)BinaryPrimitives.ReadUInt16LittleEndian(buffer);
        }

        return result;
    }

    private static KeyValuePair<AVPairKey, byte[]> ReadAVPair(ref ReadOnlySpan<byte> buffer)
    {
        var key = (AVPairKey)LittleEndianReader.ReadUInt16(ref buffer);
        var length = LittleEndianReader.ReadUInt16(ref buffer);
        var value = ByteReader.ReadBytes(ref buffer, length);
        return new KeyValuePair<AVPairKey, byte[]>(key, value);
    }
}