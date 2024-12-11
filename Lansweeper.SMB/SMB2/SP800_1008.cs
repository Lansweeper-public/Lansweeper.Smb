// Adapted from https://referencesource.microsoft.com/#system.web/Security/Cryptography/SP800_108.cs

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Lansweeper.Smb.SMB2;

/// <summary>
///     Implements the NIST SP800-108 key derivation routine in counter mode with an HMAC PRF.
///     See: http://csrc.nist.gov/publications/nistpubs/800-108/sp800-108.pdf
/// </summary>
#pragma warning disable S101 // Types should be named in PascalCase
internal static class SP800_1008
#pragma warning restore S101 // Types should be named in PascalCase
{
    public static byte[] DeriveKey(HMAC hmac, byte[]? label, byte[]? context, int keyLengthInBits)
    {
        var labelLength = label is not null ? label.Length : 0;
        var contextLength = context is not null ? context.Length : 0;
        var buffer =
            new byte[4 /* [i]_2 */ + labelLength /* label */ + 1 /* 0x00 */ + contextLength /* context */ +
                     4 /* [L]_2 */];

        if (labelLength != 0)
        {
            Buffer.BlockCopy(label!, 0, buffer, 4, labelLength); // the 4 accounts for the [i]_2 length
        }

        if (contextLength != 0)
        {
            Buffer.BlockCopy(context!, 0, buffer, 5 + labelLength,
                contextLength); // the '5 +' accounts for the [i]_2 length, the label, and the 0x00 byte
        }

        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(5 + labelLength + contextLength), 
            (uint)keyLengthInBits);  // the '5 +' accounts for the [i]_2 length, the label, the 0x00 byte, and the context

        // Initialization
        var numBytesWritten = 0;
        var numBytesRemaining = keyLengthInBits / 8;
        var output = new byte[numBytesRemaining];

        // Calculate each K_i value and copy the leftmost bits to the output buffer as appropriate.
#pragma warning disable S1994 // "for" loop increment clauses should modify the loops' counters
        for (uint i = 1; numBytesRemaining > 0; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(buffer, i); // set the first 32 bits of the buffer to be the current iteration value

            var K_i = hmac.ComputeHash(buffer);

            // copy the leftmost bits of K_i into the output buffer
            var numBytesToCopy = Math.Min(numBytesRemaining, K_i.Length);
            Buffer.BlockCopy(K_i, 0, output, numBytesWritten, numBytesToCopy);
            numBytesWritten += numBytesToCopy;
            numBytesRemaining -= numBytesToCopy;
        }
#pragma warning restore S1994 // "for" loop increment clauses should modify the loops' counters

        // finished
        return output;
    }
}