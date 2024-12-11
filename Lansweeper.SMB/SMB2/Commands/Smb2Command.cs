using Lansweeper.Smb.Enums;
using Lansweeper.Smb.SMB2.Commands;
using Lansweeper.Smb.SMB2.Enums;
using Lansweeper.Smb.Utilities;
using System.Buffers.Binary;

namespace Lansweeper.Smb.SMB2;

public abstract class Smb2Command
{
    public Smb2Header Header { get; set; }

    protected Smb2Command(Smb2CommandName commandName)
    {
        Header = new Smb2Header(commandName);
    }

    protected Smb2Command(ReadOnlySpan<byte> buffer, Smb2Dialect dialect)
    {
        Header = new Smb2Header(buffer, dialect);
    }

    public Smb2CommandName CommandName => Header.Command;

    public ulong MessageID => Header.MessageID;

    public int Length => Smb2Header.Length + CommandLength;

    public abstract int CommandLength { get; }

    public void WriteBytes(Span<byte> buffer, Smb2Dialect dialect)
    {
        Header.WriteBytes(buffer, dialect);
        WriteCommandBytes(buffer[Smb2Header.Length..]);
    }

    public abstract void WriteCommandBytes(Span<byte> buffer);

    public byte[] GetBytes(Smb2Dialect dialect)
    {
        var buffer = new byte[Length];
        WriteBytes(buffer, dialect);
        return buffer;
    }

    public static Smb2Command ReadRequest(ref ReadOnlySpan<byte> buffer, Smb2Dialect dialect)
    {
        var commandName = (Smb2CommandName)BinaryPrimitives.ReadUInt16LittleEndian(buffer[12..]);
        Smb2Command command = commandName switch
        {
            Smb2CommandName.Negotiate => new NegotiateRequest(buffer),
            Smb2CommandName.SessionSetup => new SessionSetupRequest(buffer, dialect),
            Smb2CommandName.Logoff => new LogoffRequest(buffer, dialect),
            _ => throw new InvalidDataException($"Invalid SMB2 command 0x{(ushort)commandName:X4}"),
        };

        buffer = buffer[(int)command.Header.NextCommand..];
        return command;
    }

    public static List<Smb2Command> ReadRequestChain(ReadOnlySpan<byte> buffer, Smb2Dialect dialect)
    {
        var result = new List<Smb2Command>();
        Smb2Command command;
        do
        {
            command = ReadRequest(ref buffer, dialect);
            result.Add(command);
        } while (command.Header.NextCommand != 0);

        return result;
    }

    public static byte[] GetCommandChainBytes(List<Smb2Command> commands)
    {
        return GetCommandChainBytes(commands, null, Smb2Dialect.SMB2xx);
    }

    /// <param name="signingKey">
    ///     Message will be signed using this key if (not null and) SMB2_FLAGS_SIGNED is set.
    /// </param>
    /// <param name="dialect">
    ///     Used for signature calculation when applicable.
    /// </param>
    public static byte[] GetCommandChainBytes(List<Smb2Command> commands, byte[]? signingKey, Smb2Dialect dialect)
    {
        var totalLength = 0;
        for (var index = 0; index < commands.Count; index++)
        {
            // Any subsequent SMB2 header MUST be 8-byte aligned
            var length = commands[index].Length;
            if (index < commands.Count - 1)
            {
                var paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                totalLength += paddedLength;
            }
            else
            {
                totalLength += length;
            }
        }

        var buffer = new byte[totalLength];
        var offset = 0;
        for (var index = 0; index < commands.Count; index++)
        {
            var command = commands[index];
            var commandLength = command.Length;
            int paddedLength;
            if (index < commands.Count - 1)
            {
                paddedLength = (int)Math.Ceiling((double)commandLength / 8) * 8;
                command.Header.NextCommand = (uint)paddedLength;
            }
            else
            {
                paddedLength = commandLength;
            }

            command.WriteBytes(buffer.AsSpan(offset), dialect);
            if (command.Header.IsSigned && signingKey is not null)
            {
                // [MS-SMB2] Any padding at the end of the message MUST be used in the hash computation.
                var signature = Smb2Cryptography.CalculateSignature(signingKey, dialect, buffer, offset, paddedLength);
                // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                ByteWriter.WriteBytes(buffer.AsSpan(offset + Smb2Header.SignatureOffset, 16), signature);
            }

            offset += paddedLength;
        }

        return buffer;
    }

    public static Smb2Command ReadResponse(ref ReadOnlySpan<byte> buffer, Smb2Dialect dialect)
    {
        var command = ReadResponse(buffer, dialect);
        buffer = buffer[(int)command.Header.NextCommand..];
        return command;
    }


    public static Smb2Command ReadResponse(ReadOnlySpan<byte> buffer, Smb2Dialect dialect)
    {
        var commandName = (Smb2CommandName)BinaryPrimitives.ReadUInt16LittleEndian(buffer[12..]);
        var structureSize = BinaryPrimitives.ReadUInt16LittleEndian(buffer[Smb2Header.Length..]);

        switch (commandName)
        {
            case Smb2CommandName.Negotiate:
                {
                    if (structureSize == NegotiateResponse.DeclaredSize)
                        return new NegotiateResponse(buffer);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, dialect);
                    throw new InvalidDataException();
                }
            case Smb2CommandName.SessionSetup:
                {
                    // SESSION_SETUP Response and ERROR Response have the same declared StructureSize of 9.
                    if (structureSize == SessionSetupResponse.DeclaredSize)
                    {
                        var status = (NTStatus)BinaryPrimitives.ReadUInt32LittleEndian(buffer[8..]);
                        if (status == NTStatus.STATUS_SUCCESS || status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
                            return new SessionSetupResponse(buffer, dialect);
                        return new ErrorResponse(buffer, dialect);
                    }

                    throw new InvalidDataException();
                }
            case Smb2CommandName.Logoff:
                {
                    if (structureSize == LogoffResponse.DeclaredSize)
                        return new LogoffResponse(buffer, dialect);
                    if (structureSize == ErrorResponse.DeclaredSize)
                        return new ErrorResponse(buffer, dialect);
                    throw new InvalidDataException();
                }
            default:
                throw new InvalidDataException($"Invalid SMB2 command 0x{(ushort)commandName:X4}");
        }
    }

    public static List<Smb2Command> ReadResponseChain(ReadOnlySpan<byte> buffer, Smb2Dialect dialect)
    {
        var result = new List<Smb2Command>();
        Smb2Command command;
        do
        {
            command = ReadResponse(ref buffer, dialect);
            result.Add(command);
        } while (command.Header.NextCommand != 0);

        return result;
    }

}