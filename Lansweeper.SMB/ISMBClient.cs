using System.Net;
using Lansweeper.Smb.Enums;

namespace Lansweeper.Smb;

public interface ISmbClient
{
    uint MaxReadSize { get; }
    uint MaxWriteSize { get; }
    bool IsConnected { get; }
    public TimeSpan Timeout { get; set; }

    Task<bool> Connect(string serverName, CancellationToken cancellationToken = default);
    Task<bool> Connect(IPAddress serverAddress, CancellationToken cancellationToken = default);
    void Disconnect();

    Task<NTStatus> Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod = AuthenticationMethod.NTLMv2, CancellationToken cancellationToken = default);
    Task<NTStatus> Logoff(CancellationToken cancellationToken = default);
}