using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;
using System.Buffers.Binary;

namespace Lansweeper.Smb.SMB1.Commands;

public abstract class Smb1Command
{
    protected byte[] SMBData { get; set; } // SMB_Data
    protected byte[] SMBParameters { get; set; } // SMB_Parameters

    protected Smb1Command()
    {
        SMBParameters = [];
        SMBData = [];
    }

    protected Smb1Command(ReadOnlySpan<byte> buffer)
    {
        var wordCount = ByteReader.ReadByte(ref buffer);
        SMBParameters = ByteReader.ReadBytes(ref buffer, wordCount * 2);
        var byteCount = LittleEndianReader.ReadUInt16(ref buffer);
        SMBData = ByteReader.ReadBytes(ref buffer, byteCount);
    }

    public abstract CommandName CommandName { get; }

    public virtual byte[] GetBytes(bool isUnicode)
    {
        if (SMBParameters.Length % 2 > 0) throw new InvalidDataException("SMB_Parameters Length must be a multiple of 2");
        var length = 1 + SMBParameters.Length + 2 + SMBData.Length;
        var buffer = new byte[length];
        var wordCount = (byte)(SMBParameters.Length / 2);
        var byteCount = (ushort)SMBData.Length;

        Span<byte> span = buffer;
        ByteWriter.WriteByte(ref span, wordCount);
        ByteWriter.WriteBytes(ref span, SMBParameters);
        LittleEndianWriter.WriteUInt16(ref span, byteCount);
        ByteWriter.WriteBytes(ref span, SMBData);

        return buffer;
    }

    public static Smb1Command ReadCommand(ReadOnlySpan<byte> buffer, CommandName commandName, Smb1Header header)
    {
        return (header.Flags & HeaderFlags.Reply) > 0
            ? ReadCommandResponse(buffer, commandName, header.UnicodeFlag)
            : ReadCommandRequest(buffer, commandName, header.UnicodeFlag);
    }

    public static Smb1Command ReadCommandRequest(ReadOnlySpan<byte> buffer, CommandName commandName, bool isUnicode)
    {
        switch (commandName)
        {
            case CommandName.SMB_COM_NEGOTIATE:
                return new NegotiateRequest(buffer);
            case CommandName.SMB_COM_SESSION_SETUP_ANDX:
                {
                    var wordCount = buffer[0];
                    if (wordCount * 2 == SessionSetupAndXRequest.ParametersLength)
                        return new SessionSetupAndXRequest(buffer, isUnicode);
                    if (wordCount * 2 == SessionSetupAndXRequestExtended.ParametersLength)
                        return new SessionSetupAndXRequestExtended(buffer, isUnicode);
                    throw new InvalidDataException();
                }
            case CommandName.SMB_COM_LOGOFF_ANDX:
                return new LogoffAndXRequest(buffer);
            default:
                throw new InvalidDataException("Invalid SMB command 0x" + ((byte)commandName).ToString("X2"));
        }
    }

    public static Smb1Command ReadCommandResponse(ReadOnlySpan<byte> buffer, CommandName commandName, bool isUnicode)
    {
        var wordCount = buffer[0];
        switch (commandName)
        {
            case CommandName.SMB_COM_NEGOTIATE:
                {
                    // Both NegotiateResponse and NegotiateResponseExtended have WordCount set to 17
                    if (wordCount * 2 == NegotiateResponse.ParametersLength)
                    {
                        var capabilities = (Capabilities)BinaryPrimitives.ReadUInt32LittleEndian(buffer[20..]);
                        return capabilities.HasFlag(Capabilities.ExtendedSecurity)
                            ? new NegotiateResponseExtended(buffer)
                            : new NegotiateResponse(buffer, isUnicode);
                    }

                    if (wordCount == 0)
                        return new ErrorResponse(commandName);
                    throw new InvalidDataException();
                }
            case CommandName.SMB_COM_SESSION_SETUP_ANDX:
                {
                    if (wordCount * 2 == SessionSetupAndXResponse.ParametersLength)
                        return new SessionSetupAndXResponse(buffer, isUnicode);
                    if (wordCount * 2 == SessionSetupAndXResponseExtended.ParametersLength)
                        return new SessionSetupAndXResponseExtended(buffer, isUnicode);
                    if (wordCount == 0)
                        return new ErrorResponse(commandName);
                    throw new InvalidDataException();
                }
            case CommandName.SMB_COM_LOGOFF_ANDX:
                {
                    if (wordCount * 2 == LogoffAndXResponse.ParametersLength)
                        return new LogoffAndXResponse(buffer);
                    if (wordCount == 0)
                        return new ErrorResponse(commandName);
                    throw new InvalidDataException();
                }
            default:
                throw new InvalidDataException("Invalid SMB command 0x" + ((byte)commandName).ToString("X2"));
        }
    }

}