using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.SMB1;

/// <summary>
///     Each message has a single header and either a single command or multiple batched (AndX) commands.
///     Multiple command requests or responses can be sent in a single message.
/// </summary>
public class Smb1Message
{
    public List<Smb1Command> Commands { get; set; } = [];
    public Smb1Header Header { get; set; }

    public Smb1Message()
    {
        Header = new Smb1Header();
    }

    public Smb1Message(ReadOnlySpan<byte> buffer)
    {
        Header = new Smb1Header(buffer);
        var command = Smb1Command.ReadCommand(buffer[Smb1Header.Length..], Header.Command, Header);
        Commands.Add(command);
        while (command is SmbAndXCommand andXCommand)
        {
            if (andXCommand.AndXCommand == CommandName.SMB_COM_NO_ANDX_COMMAND) break;
            command = Smb1Command.ReadCommand(buffer[andXCommand.AndXOffset..], andXCommand.AndXCommand, Header);
            Commands.Add(command);
        }
    }

    public byte[] GetBytes()
    {
        if (Commands.Count == 0) throw new ArgumentException("Invalid command sequence");

        for (var index = 0; index < Commands.Count - 1; index++)
            if (Commands[index] is not SmbAndXCommand)
                throw new ArgumentException("Invalid command sequence");

        var lastCommand = Commands[^1];
        if (lastCommand is SmbAndXCommand lastAndXCommand)
        {
            lastAndXCommand.AndXCommand = CommandName.SMB_COM_NO_ANDX_COMMAND;
        }

        var sequence = new List<byte[]>();
        var length = Smb1Header.Length;
        byte[] commandBytes;
        for (var index = 0; index < Commands.Count - 1; index++)
        {
            var andXCommand = (SmbAndXCommand)Commands[index];
            andXCommand.AndXCommand = Commands[index + 1].CommandName;
            commandBytes = Commands[index].GetBytes(Header.UnicodeFlag);
            var nextOffset = (ushort)(length + commandBytes.Length);
            SmbAndXCommand.WriteAndXOffset(commandBytes, nextOffset);
            sequence.Add(commandBytes);
            length += commandBytes.Length;
        }

        commandBytes = lastCommand.GetBytes(Header.UnicodeFlag);
        sequence.Add(commandBytes);
        length += commandBytes.Length;

        Header.Command = Commands[0].CommandName;

        var buffer = new byte[length];
        Header.WriteBytes(buffer);
        var body = buffer.AsSpan(Smb1Header.Length);
        foreach (var bytes in sequence) ByteWriter.WriteBytes(ref body, bytes);

        return buffer;
    }

    public static Smb1Message GetSMB1Message(ReadOnlySpan<byte> buffer)
    {
        if (!Smb1Header.IsValidSMB1Header(buffer)) throw new InvalidDataException("Invalid SMB header signature");
        return new Smb1Message(buffer);
    }
}