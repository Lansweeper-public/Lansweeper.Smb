using System.Buffers.Binary;
using System.Text;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.NTLM;

public static class AuthenticationMessageUtils
{
    /// <summary>
    /// read a memory location as Ansi string based on a pointer in the buffer
    /// </summary>
    /// <param name="buffer">The pointer will contain an offset, this offset has to be relative to the buffer provided</param>
    /// <param name="bufferPointerOffset">refers to where the pointer starts in the provided buffer</param>
    public static string ReadAnsiStringBufferPointer(ReadOnlySpan<byte> buffer, int bufferPointerOffset)
    {
        var span = ReadBufferPointer(buffer, bufferPointerOffset);
        return Encoding.Default.GetString(span);
    }

    /// <summary>
    /// read a memory location as Unicode string based on a pointer in the buffer
    /// </summary>
    /// <param name="buffer">The pointer will contain an offset, this offset has to be relative to the buffer provided</param>
    /// <param name="bufferPointerOffset">refers to where the pointer starts in the provided buffer</param>
    public static string ReadUnicodeStringBufferPointer(ReadOnlySpan<byte> buffer, int bufferPointerOffset)
    {
        var span = ReadBufferPointer(buffer, bufferPointerOffset);
        return Encoding.Unicode.GetString(span);
    }

    /// <summary>
    /// read a memory location based on a pointer in the buffer
    /// </summary>
    /// <param name="buffer">The pointer will contain an offset, this offset has to be relative to the buffer provided</param>
    /// <param name="bufferPointerOffset">refers to where the pointer starts in the provided buffer</param>
    public static ReadOnlySpan<byte> ReadBufferPointer(ReadOnlySpan<byte> buffer, int bufferPointerOffset)
    {
        var length = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(bufferPointerOffset, 2));
        //var maxLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(bufferPointerOffset + 2, 2))
        var bufferOffset = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(bufferPointerOffset + 4, 4));

        if (length == 0)
            return [];
        return buffer.Slice((int)bufferOffset, length);
    }

    public static void WriteBufferPointer(Span<byte> bufferPointer, ushort bufferLength, uint bufferOffset)
    {
        LittleEndianWriter.WriteUInt16(ref bufferPointer, bufferLength);
        LittleEndianWriter.WriteUInt16(ref bufferPointer, bufferLength); // buffer length is reused for max length
        LittleEndianWriter.WriteUInt32(ref bufferPointer, bufferOffset);
    }

    public static bool IsSignatureValid(ReadOnlySpan<byte> messageBytes)
    {
        return messageBytes[..8].SequenceEqual(AuthenticateMessage.ValidSignatureInBytes.AsSpan());
    }

    /// <summary>
    ///     If NTLM v1 Extended Session Security is used, LMResponse starts with 8-byte challenge, followed by 16 bytes of
    ///     padding (set to zero).
    /// </summary>
    /// <remarks>
    ///     LMResponse is 24 bytes for NTLM v1, NTLM v1 Extended Session Security and NTLM v2.
    /// </remarks>
    public static bool IsNtlmV1ExtendedSessionSecurity(ReadOnlySpan<byte> lmResponse)
    {
        return lmResponse.Length == 24
            && lmResponse[0..8].ContainsAnyExcept((byte)0) // should be 8 bytes of challenge (at least one bytes is not zero)
            && !lmResponse[8..24].ContainsAnyExcept((byte)0); // follows by 16 bytes of padding (all bytes are zero)
    }


    /// <remarks>
    ///     NTLM v1 / NTLM v1 Extended Session Security NTResponse is 24 bytes.
    /// </remarks>
    public static bool IsNtlmV2NTResponse(ReadOnlySpan<byte> ntResponse)
    {
        return ntResponse.Length >= 16 + NtlmV2ClientChallenge.MinimumLength &&
               ntResponse[16] == NtlmV2ClientChallenge.StructureVersion &&
               ntResponse[17] == NtlmV2ClientChallenge.StructureVersion;
    }

    public static MessageTypeName GetMessageType(ReadOnlySpan<byte> messageBytes)
    {
        return (MessageTypeName)BinaryPrimitives.ReadUInt32LittleEndian(messageBytes[8..]);
    }
}