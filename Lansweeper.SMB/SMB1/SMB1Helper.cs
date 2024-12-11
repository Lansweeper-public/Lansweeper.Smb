using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1;

public static class Smb1Helper
{
    public static string ReadSMBString(ref ReadOnlySpan<byte> buffer, bool isUnicode)
    {
        return isUnicode 
            ? ByteReader.ReadNullTerminatedUTF16String(ref buffer) 
            : ByteReader.ReadNullTerminatedAnsiString(ref buffer);
    }

    public static void WriteSMBString(ref Span<byte> buffer, bool isUnicode, string value)
    {
        if (isUnicode)
            ByteWriter.WriteNullTerminatedUTF16String(ref buffer,  value);
        else
            ByteWriter.WriteNullTerminatedAnsiString(ref buffer, value);
    }
}