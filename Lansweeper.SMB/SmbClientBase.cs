using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net.Sockets;
using System.Net;
using Lansweeper.Smb.Utilities;
using Lansweeper.Smb.Enums;
using Lansweeper.Smb.Netbios.Enums;
using Lansweeper.Smb.Netbios;
using System.Buffers;
using Lansweeper.Smb.Authentication.NTLM;

namespace Lansweeper.Smb;

/// <summary>
/// contains the common code for <see cref="Smb1Client"/> and <see cref="Smb2Client"/>
/// </summary>
public abstract class SmbClientBase(INameServiceClient nameServiceClient, ILogger logger)
    : IDisposable
{
    // Constants
    public const int NetBiosOverTCPPort = 139;
    public const int DirectTCPPort = 445;

    // Settings
    public SMBTransportType TransportType { get; set; }
    /// <summary>
    /// Smb1Client will do multiple requests, this is the timeout for each request
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    // State
    public bool IsConnected { get; private set; }
    private Socket? _clientSocket;
    /// <summary>
    /// indicates how large the buffer should be for receiving packets
    /// By default it is set to <see cref="SessionPacket.MaxSessionPacketLength"/>
    /// in SMB2, you can increase this to the maximum packet size
    /// </summary>
    protected int BufferSize { get; set; } = SessionPacket.MaxSessionPacketLength;

    // Info about the current connection
    /// <summary>
    /// If the NetBiosServiceName is known, it will be used to connect to the server
    /// Set this to avoid NetBIOS probing
    /// </summary>
    public string? NetBiosServiceName { get; set; }
    public string? NetBiosComputerName { get; protected set; }
    public string? NetBiosDomainName { get; protected set; }
    public string? DnsDomainName { get; protected set; }
    public string? DnsComputerName { get; protected set; }
    public string? NtlmTargetName { get; protected set; }
    public NtlmVersion? NtlmVersion { get; protected set; }

    public virtual void Disconnect()
    {
        if (IsConnected)
        {
            _clientSocket?.Disconnect(false);
        }
        _clientSocket?.Dispose();
        _clientSocket = null;
        IsConnected = false;
        BufferSize = SessionPacket.MaxSessionPacketLength;
    }

    public virtual Task<bool> Connect(string serverName, CancellationToken cancellationToken = default)
    {
        IPAddress[] hostAddresses = Dns.GetHostAddresses(serverName);
        if (hostAddresses.Length == 0)
            throw new ArgumentException($"Cannot resolve host name {serverName} to an IP address");
        IPAddress serverAddress = IPAddressHelper.SelectAddressPreferIPv4(hostAddresses);
        return Connect(serverAddress, cancellationToken);
    }

    public virtual async Task<bool> Connect(IPAddress serverAddress, CancellationToken cancellationToken = default)
    {
        if (IsConnected) return true;

        bool success = await ConnectInternal(serverAddress, cancellationToken).ConfigureAwait(false);

        if (!success)
        {
            Disconnect();
        }

        IsConnected = success;
        return IsConnected;
    }

    private async Task<bool> ConnectInternal(IPAddress serverAddress, CancellationToken cancellationToken)
    {
        // Try to connect socket
        var port = TransportType == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort;
        _clientSocket = await ConnectSocket(serverAddress, port, cancellationToken).ConfigureAwait(false);
        if (_clientSocket is null) return false;

        // If NetBIOS, set up transport layer
        if (TransportType == SMBTransportType.NetBiosOverTCP)
        {
            bool setupSuccess = await SetupUpNetbios(serverAddress, port, cancellationToken);
            if (!setupSuccess) return false;
        }

        // Negotiate Dialect
        bool negotiationSuccessful = await NegotiateDialect(cancellationToken);
        if (!negotiationSuccessful) return false;

        return true;
    }

    protected async Task<Socket?> ConnectSocket(IPAddress serverAddress, int port, CancellationToken cancellationToken)
    {
        int timeoutInMilliseconds = (int)Timeout.TotalMilliseconds;
        _clientSocket = new Socket(serverAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            ReceiveTimeout = timeoutInMilliseconds, // for socket.Receive (only the synchronous methods)
            SendTimeout = timeoutInMilliseconds, // for socket.Send (only the synchronous methods)
        };

        using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linkedCts.CancelAfter(Timeout);
        var startTime = Stopwatch.GetTimestamp();

        try
        {
            await _clientSocket.ConnectAsync(serverAddress, port, linkedCts.Token);
            return _clientSocket;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) // only handle if caused by timeout
        {
            var elapsed = Stopwatch.GetElapsedTime(startTime);
#pragma warning disable S6667 // Logging in a catch clause should pass the caught exception as a parameter.
            logger.LogDebug("Socket connection timed out after {Elapsed}ms", elapsed.TotalMilliseconds);
#pragma warning restore S6667 // Logging in a catch clause should pass the caught exception as a parameter.
            Disconnect();
            return null;
        }
        catch (SocketException ex)
        {
            logger.LogDebug(ex, "SocketException on connection {SocketErrorCode}", ex.SocketErrorCode.ToString());
            Disconnect();
            return null;
        }
    }

    private async Task<bool> SetupUpNetbios(IPAddress serverAddress, int port, CancellationToken cancellationToken)
    {
        Debug.Assert(_clientSocket is not null, $"{nameof(_clientSocket)} cannot be null here");

        var callingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
        SessionRequestPacket sessionRequest;
        SessionPacket? reply;

        // if NetBiosServiceName is not known, first try general called name
        if (string.IsNullOrEmpty(NetBiosServiceName))
        {
            var generalCalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServerService);
            sessionRequest = new SessionRequestPacket(generalCalledName, callingName);

            reply = await TrySendNetbiosSessionPacket(sessionRequest, cancellationToken).ConfigureAwait(false);
            if (reply is PositiveSessionResponsePacket) return true; // success, return

            // try again with a specific called name
            // reconnect socket
            try
            {
                using CancellationTokenSource disconnectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                disconnectCts.CancelAfter(Timeout);
                await _clientSocket.DisconnectAsync(false, disconnectCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) // only handle the timeout
            {
#pragma warning disable S6667 // Logging in a catch clause should pass the caught exception as a parameter.
                logger.LogDebug("Socket disconnect timed out");
#pragma warning restore S6667 // Logging in a catch clause should pass the caught exception as a parameter.
            }

            _clientSocket = await ConnectSocket(serverAddress, port, cancellationToken);
            if (_clientSocket is null) return false;

            // get specific name
            var serverName = await nameServiceClient
                            .SendProbe(serverAddress, cancellationToken)
                            .ConfigureAwait(false);
            if (serverName?.ServiceName is null) return false;

            NetBiosServiceName = serverName.ServiceName; // remember for next time
        }

        // NetBiosServiceName is now known
        string calledName = NetBiosUtils.GetMSNetBiosName(NetBiosServiceName, NetBiosSuffix.FileServerService);
        sessionRequest = new SessionRequestPacket(calledName, callingName);
        reply = await TrySendNetbiosSessionPacket(sessionRequest, cancellationToken);
        return reply is PositiveSessionResponsePacket;
    }

    protected async Task<SessionPacket?> TrySendNetbiosSessionPacket(SessionPacket packet, CancellationToken cancellationToken)
    {
        Debug.Assert(_clientSocket is not null, $"{nameof(_clientSocket)} cannot be null here");

        byte[]? buffer = null;
        var startTime = Stopwatch.GetTimestamp();

        try
        {
            // send request
            using CancellationTokenSource sendCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            sendCts.CancelAfter(Timeout);
            var packetBytes = packet.GetBytes();
            await _clientSocket.SendAsync(packetBytes, sendCts.Token);

            // receive reply
            // rent buffer
            buffer = ArrayPool<byte>.Shared.Rent(BufferSize);

            // receive bytes
            int numberOfBytesReceived = await TryReceiveNetBiosSessionPacketBytes(buffer, _clientSocket, cancellationToken);

            // parse reply
            try
            {
                var result = SessionPacket.GetSessionPacket(buffer.AsSpan(0, numberOfBytesReceived));
                return result;
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "could not parse NetBIOS SessionPacket");
                return null;
            }
        }
#pragma warning disable S6667 // Logging in a catch clause should pass the caught exception as a parameter.
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) // only handle if caused by timeout
        {
            var elapsed = Stopwatch.GetElapsedTime(startTime);
            logger.LogDebug("NetBIOS session packet timed out after {Elapsed}ms", elapsed.TotalMilliseconds);
            return null;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            // this is likely to happen if the server doesn't support a certain version of SMB. don't log the entire exception.
            logger.LogDebug("SocketException during NetBIOS session packet {SocketError}", ex.SocketErrorCode);
            return null;
        }
#pragma warning restore S6667 // Logging in a catch clause should pass the caught exception as a parameter.
        catch (SocketException ex)
        {
            logger.LogDebug(ex, "SocketException during NetBIOS session packet {SocketError}", ex.SocketErrorCode);
            return null;
        }
        catch (ObjectDisposedException)
        {
            Debug.Fail("should not use an already disposed object");
            return null;
        }
        catch (InvalidDataException ex)
        {
            logger.LogDebug(ex, "Invalid data received for NetBIOS session packet");
            return null;
        }
        finally
        {
            if (buffer is not null)
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    /// <returns>number of bytes received </returns>
    private async Task<int> TryReceiveNetBiosSessionPacketBytes(Memory<byte> buffer, Socket socket, CancellationToken cancellationToken)
    {
        using CancellationTokenSource receiveCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        receiveCts.CancelAfter(Timeout);

        int numberOfBytesReceived = 0;
        int? expectedLength = null;
        while (true)
        {
            int received = await socket.ReceiveAsync(buffer.Slice(numberOfBytesReceived), receiveCts.Token);
            numberOfBytesReceived += received;

            if (numberOfBytesReceived < SessionPacket.HeaderLength)
            {
                // not enough bytes received yet to determine the length
                continue;
            }

            if (!expectedLength.HasValue)
            {
                expectedLength = SessionPacket.GetSessionPacketLength(buffer.Span);
            }

            if (expectedLength == numberOfBytesReceived)
            {
                // got a complete packet
                break;
            }

            if (expectedLength < numberOfBytesReceived)
            {
                // got too many bytes
                throw new InvalidDataException("Received more bytes than expected for NetBIOS session packet");
            }
        }

        return numberOfBytesReceived;
    }

    /// <summary>
    /// Negotiate the dialect with the server.
    /// This is very different for SMB1 and SMB2
    /// Use this method to extract any useful information during the negotiation
    /// </summary>
    protected abstract Task<bool> NegotiateDialect(CancellationToken cancellationToken);


    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        Disconnect();
    }
}
