#nullable enable
namespace Lansweeper.Smb.Authentication;

public interface IAuthenticationClient
{
    /// <returns>Credentials blob or null if security blob is invalid</returns>
    byte[]? InitializeSecurityContext(byte[] securityBlob);

    byte[]? GetSessionKey();
}