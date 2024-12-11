using System.Net;

namespace Lansweeper.Smb.Netbios;

public interface INameServiceClient
{
    public TimeSpan Timeout { get; set; }

    //Task<string?> GetServerNameAsync(IPAddress serverAddress, CancellationToken cancellationToken = default);
    Task<NbnsProbeResult?> SendProbe(IPAddress serverAddress, CancellationToken cancellationToken = default);

}