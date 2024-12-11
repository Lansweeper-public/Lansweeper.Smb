using System.Net;
using System.Net.Sockets;

namespace Lansweeper.Smb.Utilities;

public static class IPAddressHelper
{
    public static IPAddress SelectAddressPreferIPv4(IPAddress[] hostAddresses)
    {
        return Array.Find(hostAddresses, static hostAddress => hostAddress.AddressFamily == AddressFamily.InterNetwork) ?? hostAddresses[0];
    }
}