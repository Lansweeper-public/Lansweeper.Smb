using System.Net;
using Lansweeper.Smb.Authentication;
using Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;
using Lansweeper.Smb.Authentication.NTLM;
using Lansweeper.Smb.Enums;
using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.SMB2.Commands;
using Lansweeper.Smb.SMB2.Commands.NegotiateContexts;
using Lansweeper.Smb.SMB2.Enums;
using Microsoft.Extensions.Logging;

namespace Lansweeper.Smb.SMB2;

public class Smb2Client(INameServiceClient nameServiceClient, ILogger<Smb2Client> logger)
    : SmbClientBase(nameServiceClient, logger), ISmbClient
{
    // Constants
    public static readonly uint ClientMaxTransactSize = 1048576;
    public static readonly uint ClientMaxReadSize = 1048576;
    public static readonly uint ClientMaxWriteSize = 1048576;

    private static readonly ushort DesiredCredits = 16;


    // Settings
    public bool SupportSmb302 { get; set; } = true;
    public bool SupportSmb311 { get; set; } = true;

    // State
    public bool IsLoggedIn { get; private set; }


    // Connection Info
    public uint MaxTransactSize { get; private set; }
    public uint MaxReadSize { get; private set; }
    public uint MaxWriteSize { get; private set; }
    private string? _serverName;
    private Smb2Dialect _dialect = Smb2Dialect.Unknown;
    private byte[]? _securityBlob;
    private byte[]? _preauthIntegrityHashValue;
    private uint _messageID;
    private ulong _sessionID;
    private ushort _availableCredits = 1;


    public override void Disconnect()
    {
        base.Disconnect();
        _serverName = null;
        _securityBlob = null;
        _preauthIntegrityHashValue = null;
        _dialect = Smb2Dialect.Unknown;
        _messageID = 0;
        _sessionID = 0;
        _availableCredits = 1;
        IsLoggedIn = false;
    }

    public override Task<bool> Connect(string serverName, CancellationToken cancellationToken = default)
    {
        // remember server name for login
        _serverName = serverName;

        return base.Connect(serverName, cancellationToken);
    }

    public override Task<bool> Connect(IPAddress serverAddress, CancellationToken cancellationToken = default)
    {
        // remember server name for login
        _serverName ??= serverAddress.ToString();

        return base.Connect(serverAddress, cancellationToken);
    }


    /// <remarks>
    /// This is the SMB2-Only Negotiate as described in 3.2.4.2.2.2
    /// The Multi-Protocol Negotiate is not implemented as not required by Lansweeper
    /// </summary>
    protected async override Task<bool> NegotiateDialect(CancellationToken cancellationToken)
    {
        var request = new NegotiateRequest
        {
            SecurityMode = SecurityMode.SigningEnabled,
            Capabilities = Capabilities.Encryption,
            ClientGuid = Guid.NewGuid(),
            ClientStartTime = DateTime.Now,
        };
        request.Dialects.Add(Smb2Dialect.SMB202);
        request.Dialects.Add(Smb2Dialect.SMB210);
        request.Dialects.Add(Smb2Dialect.SMB300);
        if (SupportSmb302)
        {
            request.Dialects.Add(Smb2Dialect.SMB302);
        }
        if (SupportSmb311)
        {
            request.Dialects.Add(Smb2Dialect.SMB311);
            request.NegotiateContextList = GetNegotiateContextList();
            _preauthIntegrityHashValue = new byte[64];
        }

        // send negotiate request
        Smb2Command? response = await TrySendCommand(request, cancellationToken);

        // validate response
        if (response is null) return false;

        if (response is not NegotiateResponse negotiateResponse)
        {
            logger.LogDebug("Unexpected response to negotiate request: {Response}", response);
            return false;
        }

        if (negotiateResponse.Header.Status != NTStatus.STATUS_SUCCESS)
        {
            logger.LogDebug("Negotiate request failed with status {Status}", negotiateResponse.Header.Status);
            return false;
        }

        // increase buffer size if server supports large MTU
        if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
        {
            // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client SHOULD disconnect the connection.
            // Note: Windows clients do not enforce the MaxTransactSize value.
            // We use a value that we have observed to work well with both Microsoft and non-Microsoft servers.
            // see https://github.com/TalAloni/SMBLibrary/issues/239
            var serverMaxTransactSize = (int)Math.Max(negotiateResponse.MaxTransactSize, negotiateResponse.MaxReadSize);
            var maxPacketSize = SessionPacket.HeaderLength + (int)Math.Min(serverMaxTransactSize, ClientMaxTransactSize) + 256;
            if (maxPacketSize > BufferSize)
            {
                BufferSize = maxPacketSize;
            }
        }

        // update state
        _dialect = negotiateResponse.DialectRevision;
        MaxTransactSize = Math.Min(negotiateResponse.MaxTransactSize, ClientMaxTransactSize);
        MaxReadSize = Math.Min(negotiateResponse.MaxReadSize, ClientMaxReadSize);
        MaxWriteSize = Math.Min(negotiateResponse.MaxWriteSize, ClientMaxWriteSize);
        _securityBlob = negotiateResponse.SecurityBuffer;

        return true;
    }

    /// <remarks>SMB 3.1.1 only</remarks>
    private static List<NegotiateContext> GetNegotiateContextList()
    {
        PreAuthIntegrityCapabilities preAuthIntegrityCapabilities = new();
        preAuthIntegrityCapabilities.HashAlgorithms.Add(HashAlgorithm.SHA512);
        preAuthIntegrityCapabilities.Salt = new byte[32];
        Random.Shared.NextBytes(preAuthIntegrityCapabilities.Salt);

        EncryptionCapabilities encryptionCapabilities = new();
        encryptionCapabilities.Ciphers.Add(CipherAlgorithm.Aes128Ccm);

        return [preAuthIntegrityCapabilities, encryptionCapabilities];
    }

    private async Task<Smb2Command?> TrySendCommand(Smb2Command request, CancellationToken cancellationToken)
    {
        if (_dialect == Smb2Dialect.SMB202 || TransportType == SMBTransportType.NetBiosOverTCP)
        {
            request.Header.CreditCharge = 0;
            request.Header.Credits = 1;
            _availableCredits -= 1;
        }
        else
        {
            if (request.Header.CreditCharge == 0) request.Header.CreditCharge = 1;

            if (_availableCredits < request.Header.CreditCharge) throw new InvalidOperationException("Not enough credits");

            _availableCredits -= request.Header.CreditCharge;

            if (_availableCredits < DesiredCredits)
                request.Header.Credits += (ushort)(DesiredCredits - _availableCredits);
        }

        request.Header.MessageID = _messageID;
        request.Header.SessionID = _sessionID;

        // ignore the signing and encryption, we only send negotiate and session setup requests
        // which don't need signing or encryption

        byte[] trailer = request.GetBytes(_dialect);
        if (_preauthIntegrityHashValue != null && (request is NegotiateRequest || request is SessionSetupRequest))
        {
            _preauthIntegrityHashValue = Smb2Cryptography.ComputeHash(HashAlgorithm.SHA512,
                [.. _preauthIntegrityHashValue, .. trailer]);
        }

        SessionMessagePacket packet = new(trailer);
        SessionPacket? netbiosResponse = await TrySendNetbiosSessionPacket(packet, cancellationToken);

        if (_dialect == Smb2Dialect.SMB202 || TransportType == SMBTransportType.NetBiosOverTCP)
            _messageID++;
        else
            _messageID += request.Header.CreditCharge;

        if (netbiosResponse is null) return null;

        var response = Smb2Command.ReadResponse(netbiosResponse.Trailer, _dialect);

        _availableCredits += response.Header.Credits;

        return response;
    }

    public async Task<NTStatus> Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod = AuthenticationMethod.NTLMv2, CancellationToken cancellationToken = default)
    {
        if (!IsConnected) throw new InvalidOperationException("A connection must be successfully established before attempting login");
        if (_securityBlob is null) throw new InvalidOperationException("Negotiate must be successful before attempting login");

        var spn = string.Format("cifs/{0}", _serverName);
        var authenticationClient =
            new NtlmAuthenticationClient(domainName, userName, password, spn, authenticationMethod);

        var negotiateMessage = authenticationClient.InitializeSecurityContext(_securityBlob);
        if (negotiateMessage == null) return NTStatus.SEC_E_INVALID_TOKEN;

        // send initial Session Setup Request
        var request = new SessionSetupRequest
        {
            SecurityMode = SecurityMode.SigningEnabled,
            SecurityBuffer = negotiateMessage
        };
        var response = await TrySendCommand(request, cancellationToken);

        // more processing required
        while (response is SessionSetupResponse sessionSetupResponse && response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
        {
            var authenticateMessage =
                authenticationClient.InitializeSecurityContext(sessionSetupResponse.SecurityBuffer);
            if (authenticateMessage == null) return NTStatus.SEC_E_INVALID_TOKEN;

            _sessionID = response.Header.SessionID;
            request = new SessionSetupRequest
            {
                SecurityMode = SecurityMode.SigningEnabled,
                SecurityBuffer = authenticateMessage
            };
            response = await TrySendCommand(request, cancellationToken);
        }

        if (response is SessionSetupResponse)
        {
            IsLoggedIn = response.Header.Status == NTStatus.STATUS_SUCCESS;

            // if logged in, we can now get signing and encryption keys
            // this is skipped for now as we don't need it

            return response.Header.Status;
        }

        return NTStatus.STATUS_INVALID_SMB;
    }

    public async Task<NTStatus> Logoff(CancellationToken cancellationToken = default)
    {
        if (!IsConnected) throw new InvalidOperationException("A login session must be successfully established before attempting logoff");

        var request = new LogoffRequest();
        var response = await TrySendCommand(request, cancellationToken);

        if (response is not null)
        {
            IsLoggedIn = response.Header.Status != NTStatus.STATUS_SUCCESS;
            return response.Header.Status;
        }

        return NTStatus.STATUS_INVALID_SMB;
    }
}