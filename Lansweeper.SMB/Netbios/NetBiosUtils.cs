using System.Text;
using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Netbios;

public static class NetBiosUtils
{
    /// <summary>
    ///     The NetBIOS naming convention allows for 16 characters in a NetBIOS name.
    ///     Microsoft, however, limits NetBIOS names to 15 characters and uses the 16th character as a NetBIOS suffix
    ///     See http://support.microsoft.com/kb/163409/en-us
    /// </summary>
    public static string GetMSNetBiosName(string name, NetBiosSuffix suffix)
    {
        if (name.Length > 15)
            name = name.Substring(0, 15);
        else if (name.Length < 15) name = name.PadRight(15);

        return name + (char)suffix;
    }

    public static string GetNameFromMSNetBiosName(string netBiosName)
    {
        if (netBiosName.Length != 16) throw new ArgumentException("Invalid MS NetBIOS name");

        return netBiosName.AsSpan(0, 15).TrimEnd(' ').ToString();
    }

    public static NetBiosSuffix GetSuffixFromMSNetBiosName(string netBiosName)
    {
        if (netBiosName.Length != 16) throw new ArgumentException("Invalid MS NetBIOS name");

        return (NetBiosSuffix)netBiosName[15];
    }

    public static byte[] EncodeName(string name, NetBiosSuffix suffix, string scopeID)
    {
        var netBiosName = GetMSNetBiosName(name, suffix);
        return EncodeName(netBiosName, scopeID);
    }

    /// <param name="netBiosName">NetBIOS name</param>
    /// <param name="scopeID">dot-separated labels, formatted per DNS naming rules</param>
    public static byte[] EncodeName(string netBiosName, string scopeID)
    {
        var domainName = FirstLevelEncoding(netBiosName, scopeID);
        return SecondLevelEncoding(domainName);
    }

    // The conversion of a NetBIOS name to a format complying with DNS "best practices".
    // NetBIOS names may contain characters which are not considered valid for use in DNS names,
    // yet RFC 1001 and RFC 1002 attempted to map the NetBIOS name space into the DNS name space.
    // To work around this conflict, NetBIOS names are encoded by splitting each byte of the name
    // into two nibbles and then adding the value of 'A' (0x41).
    // Thus, the '&' character (0x26) would be encoded as "CG".
    // NetBIOS names are usually padded with spaces before being encoded. 
    /// <param name="netBiosName">NetBIOS name</param>
    /// <param name="scopeID">dot-separated labels, formatted per DNS naming rules</param>
    public static string FirstLevelEncoding(string netBiosName, string scopeID)
    {
        // RFC 1001: NetBIOS names as seen across the client interface to NetBIOS are exactly 16 bytes long
        if (netBiosName.Length != 16) throw new ArgumentException("Invalid MS NetBIOS name");

        var builder = new StringBuilder();
        for (var index = 0; index < netBiosName.Length; index++)
        {
            var c = (byte)netBiosName[index];
            var high = (byte)(0x41 + (c >> 4));
            var low = (byte)(0x41 + (c & 0x0F));
            builder.Append((char)high);
            builder.Append((char)low);
        }

        if (scopeID.Length > 0)
        {
            builder.Append('.');
            builder.Append(scopeID);
        }

        return builder.ToString();
    }

    // Domain names messages are expressed in terms of a sequence
    // of labels.  Each label is represented as a one octet length
    // field followed by that number of octets.  Since every domain
    // name ends with the null label of the root, a compressed
    // domain name is terminated by a length byte of zero
    /// <summary>
    ///     The on-the-wire format of an NBT name. The encoding scheme replaces the familiar dot characters
    ///     used in DNS names with a byte containing the length of the next label.
    /// </summary>
    /// <exception cref="ArgumentException"/>
    public static byte[] SecondLevelEncoding(string domainName)
    {
        string[] labels = domainName.Split('.');
        var length = 1; // null terminator
        for (var index = 0; index < labels.Length; index++)
        {
            length += 1 + labels[index].Length;
            if (labels[index].Length > 63) throw new ArgumentException("Invalid NetBIOS label length");
        }

        var result = new byte[length];

        var resultSpan = result.AsSpan();
        foreach (var label in labels)
        {
            ByteWriter.WriteByte(ref resultSpan, (byte)label.Length);
            ByteWriter.WriteAnsiString(ref resultSpan, label, label.Length);
        }
        ByteWriter.WriteByte(ref resultSpan, 0); // null termination

        return result;
    }

    public static string DecodeName(ref ReadOnlySpan<byte> buffer)
    {
        var domainName = SecondLevelDecoding(ref buffer);
        var dotIndex = domainName.IndexOf('.');
        var name = dotIndex switch
        {
            > -1 => domainName[..dotIndex],
            _ => domainName,
        };
        return FirstLevelDecoding(name);
    }

    /// <exception cref="ArgumentException"/>
    ///
    public static string SecondLevelDecoding(ref ReadOnlySpan<byte> buffer)
    {
        StringBuilder builder = new();

        var labelLength = ByteReader.ReadByte(ref buffer);
        while (labelLength > 0)
        {
            if (builder.Length > 0) builder.Append('.');

            // The high order two bits of the length field must be zero
            if (labelLength > 63) throw new ArgumentException("Invalid NetBIOS label length");

            var label = ByteReader.ReadAnsiString(ref buffer, labelLength);
            builder.Append(label);

            labelLength = ByteReader.ReadByte(ref buffer);
        }

        return builder.ToString();
    }

    public static string FirstLevelDecoding(string name)
    {
        var builder = new StringBuilder();

        for (var index = 0; index < name.Length; index += 2)
        {
            var c0 = (byte)name[index];
            var c1 = (byte)name[index + 1];
            var high = (byte)(((c0 - 0x41) & 0xF) << 4);
            var low = (byte)((c1 - 0x41) & 0xF);
            var c = (byte)(high | low);
            builder.Append((char)c);
        }

        return builder.ToString();
    }

    /// <summary>
    ///     Will write a 2 bytes pointer to a name
    ///     Note: NetBIOS implementations can only use label string pointers in Name Service packets
    /// </summary>
    public static void WriteNamePointer(Stream stream, int nameOffset)
    {
        var pointer = (ushort)(0xC000 | (nameOffset & 0x3FFF));
        BigEndianWriter.WriteUInt16(stream, pointer);
    }
}