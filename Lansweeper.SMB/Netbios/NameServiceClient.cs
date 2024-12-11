using System.Net;
using System.Net.Sockets;
using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Utilities;
using Microsoft.Extensions.Logging;

namespace Lansweeper.Smb.Netbios;

public class NameServiceClient(ILogger<NameServiceClient> logger) : INameServiceClient
{
    public const int NetBiosNameServicePort = 137;

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    public async Task<NbnsProbeResult?> SendProbe(IPAddress serverAddress, CancellationToken cancellationToken = default)
    {
        string questionName = "*".PadRight(16, '\0');
        var request = new NodeStatusRequest(questionName);
        var response = await SendNodeStatusRequestAsync(request, serverAddress, cancellationToken).ConfigureAwait(false);

        if (response is null) return null;

        NbnsProbeResult result = MapNodeStatusResponseToProbeResult(response);
        return result;
    }

    private static NbnsProbeResult MapNodeStatusResponseToProbeResult(NodeStatusResponse response)
    {
        string rnpName = string.Empty;
        NbnsProbeResult result = new();

        // mac address is located in the statistics unit id
        ReadOnlySpan<byte> macBytes = response.Statistics.UnitID.AsSpan();
        if (macBytes.Length >= 6)
        {
            result.MacAddress = macBytes[..6].ToMacString();
        }

        foreach (var (name, flags) in response.Names)
        {
            var suffix = NetBiosUtils.GetSuffixFromMSNetBiosName(name);

            if (string.IsNullOrWhiteSpace(name)) continue;

            // look for the service name
            if (suffix == NetBiosSuffix.FileServerService)
            { 
                result.ServiceName = name.Trim('\0', ' ');
            }
            else if (suffix == NetBiosSuffix.WorkstationService && flags.IsActiveName)
            {

                // look for the computer name (or rpn Name as fallback)
                if (string.IsNullOrWhiteSpace(result.ComputerName) && flags.IsUnique)
                {
                    var nameCleaned = name.Trim('\0', ' ');

                    if (nameCleaned.StartsWith("is~", StringComparison.InvariantCultureIgnoreCase)) // IIS
                    {
                        continue;
                    }

                    if (nameCleaned.StartsWith("rnp", StringComparison.InvariantCultureIgnoreCase))
                    {
                        rnpName = nameCleaned;
                    }
                    else
                    {
                        result.ComputerName = nameCleaned;
                    }
                }

                // look for the domain name
                else if (string.IsNullOrWhiteSpace(result.DomainName) && flags.IsGroupName)
                {
                    var nameCleaned = name.Trim('\0', ' ');

                    if (nameCleaned.StartsWith("inet~", StringComparison.InvariantCultureIgnoreCase)) // IIS
                    {
                        continue;
                    }

                    result.DomainName = nameCleaned;
                }
            }
        }

        // if no computer name was found, use the rpn name
        if (string.IsNullOrWhiteSpace(result.ComputerName))
        {
            result.ComputerName = rnpName;
        }

        // if no computer name was found, use the name from the response
        if (string.IsNullOrWhiteSpace(result.ComputerName))
        {
            var nameCleaned = response.Resource.Name.Trim('\0', ' ');
            if (nameCleaned != "*")
            {
                result.ComputerName = nameCleaned;
            }
        }

        return result;
    }

    private async Task<NodeStatusResponse?> SendNodeStatusRequestAsync(NodeStatusRequest request, IPAddress serverAddress, CancellationToken cancellationToken)
    {
        try
        {
            using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var linkedCancellationToken = timeoutCts.Token; // this token will be cancelled both when timeout occurs or original token is cancelled

            using var client = new UdpClient();
            var serverEndPoint = new IPEndPoint(serverAddress, NetBiosNameServicePort);

            var requestBytes = request.GetBytes();
            timeoutCts.CancelAfter(Timeout);
            await client.SendAsync(requestBytes, serverEndPoint, linkedCancellationToken).ConfigureAwait(false);
            var receiveResult = await client.ReceiveAsync(linkedCancellationToken).ConfigureAwait(false);
            return new NodeStatusResponse(receiveResult.Buffer);
        }
#pragma warning disable S6667 // Logging in a catch clause should pass the caught exception as a parameter.
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) // not cancelled with original token --> must be caused by timeout
        {
            logger.LogDebug("The operation has timed out.");
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            // when an ICMP error is received, port is likely to be closed
            // It seems this behavior has changed in Windows 10, and it no longer throws a SocketException with SocketError.ConnectionReset
            logger.LogDebug("The operation has been interrupted by an ICMP error.");
        }
#pragma warning restore S6667 // Logging in a catch clause should pass the caught exception as a parameter.
        catch (Exception ex)
        {
            logger.LogDebug(ex, "An error occurred while sending the NetBIOS Node Status Request.");
        }

        return null;
    }
}