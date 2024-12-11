using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;

namespace Lansweeper.Smb.SMB1.Commands;

/// <summary>
///     The Command trailer of an error response message.
///     See [MS-CIFS]3.3.4.1.2 - Sending Any Error Response Message.
/// </summary>
public class ErrorResponse(CommandName commandName) : Smb1Command
{
    public override CommandName CommandName => commandName;
}