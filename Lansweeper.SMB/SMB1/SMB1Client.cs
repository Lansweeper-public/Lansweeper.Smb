using Lansweeper.Smb.Enums;
using Lansweeper.Smb.Netbios;
using Microsoft.Extensions.Logging;
using Lansweeper.Smb.SMB1.Commands;
using Lansweeper.Smb.SMB1.Enums;
using Lansweeper.Smb.Utilities;
using Lansweeper.Smb.Authentication.NTLM;
using Lansweeper.Smb.Authentication;
using System.Diagnostics;

namespace Lansweeper.Smb.SMB1;

public sealed class Smb1Client(INameServiceClient nameServiceClient, ILogger<Smb1Client> logger)
    : SmbClientBase(nameServiceClient, logger), ISmbClient
{
    // Constants
    private const string NTLanManagerDialect = "NT LM 0.12";
    private const ushort ClientMaxBufferSize = 65535; // Valid range: 512 - 65535
    private const ushort ClientMaxMpxCount = 1;

    public uint MaxReadSize =>
    (uint)ClientMaxBufferSize - (Smb1Header.Length + 3 + 24 /* = ReadAndXResponse.ParametersLength*/);

    public uint MaxWriteSize
    {
        get
        {
            var result = ServerMaxBufferSize -
                         (Smb1Header.Length + 3 + 24 /* = WriteAndXRequest.ParametersFixedLength*/ + 4);
            if (Unicode) --result;
            return result;
        }
    }

    // Settings
    public bool ForceExtendedSecurity { get; set; } = true;

    // State
    public bool IsLoggedIn { get; private set; }

    // Connection Info
    public bool Unicode { get; private set; }
    public bool LargeFiles { get; private set; }
    public bool InfoLevelPassthrough { get; private set; }
    public bool LargeRead { get; private set; }
    public bool LargeWrite { get; private set; }
    public uint ServerMaxBufferSize { get; private set; }
    public string HostName { get; private set; } = string.Empty;
    public string DomainName { get; private set; } = string.Empty;
    public string NativeLM { get; set; } = string.Empty;
    public string NativeOs { get; set; } = string.Empty;
    public ushort MaxMpxCount { get; private set; }
    public bool UsesExtendedSecurity => _securityBlob is not null;
    private ushort _userId;
    private byte[]? _securityBlob; // only set when using extended security
    private byte[]? _serverChallenge; // only set when not using extended security


    public override void Disconnect()
    {
        base.Disconnect();
        _userId = 0;
    }


    protected override async Task<bool> NegotiateDialect(CancellationToken cancellationToken)
    {
        // Create Message
        var request = new NegotiateRequest();
        request.Dialects.Add(NTLanManagerDialect);
        Smb1Message message = CreateSmbMessage(request);

        // send message
        var reply = await TrySendSmbMessage(message, cancellationToken);

        // receive reply
        if (reply is null) return false;

        try
        {
            bool success = ProcessNegotiationResponse(reply);
            return success;
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "could not parse negotiation response");
            return false;
        }
    }

    private bool ProcessNegotiationResponse(Smb1Message reply)
    {
        if (reply.Commands[0] is NegotiateResponse response && !ForceExtendedSecurity)
        {
            DomainName = response.DomainName;
            HostName = response.ServerName;
            Unicode = (response.Capabilities & Capabilities.Unicode) > 0;
            LargeFiles = (response.Capabilities & Capabilities.LargeFiles) > 0;
            var ntSMB = (response.Capabilities & Capabilities.NTSMB) > 0;
            var rpc = (response.Capabilities & Capabilities.RpcRemoteApi) > 0;
            var ntStatusCode = (response.Capabilities & Capabilities.NTStatusCode) > 0;
            InfoLevelPassthrough = (response.Capabilities & Capabilities.InfoLevelPassthrough) > 0;
            LargeRead = (response.Capabilities & Capabilities.LargeRead) > 0;
            LargeWrite = (response.Capabilities & Capabilities.LargeWrite) > 0;
            ServerMaxBufferSize = response.MaxBufferSize;
            MaxMpxCount = Math.Min(response.MaxMpxCount, ClientMaxMpxCount);
            _serverChallenge = response.Challenge;
            return ntSMB && rpc && ntStatusCode;
        }

        if (reply.Commands[0] is NegotiateResponseExtended responseExt)
        {
            Unicode = (responseExt.Capabilities & Capabilities.Unicode) > 0;
            LargeFiles = (responseExt.Capabilities & Capabilities.LargeFiles) > 0;
            var ntSMB = (responseExt.Capabilities & Capabilities.NTSMB) > 0;
            var rpc = (responseExt.Capabilities & Capabilities.RpcRemoteApi) > 0;
            var ntStatusCode = (responseExt.Capabilities & Capabilities.NTStatusCode) > 0;
            InfoLevelPassthrough = (responseExt.Capabilities & Capabilities.InfoLevelPassthrough) > 0;
            LargeRead = (responseExt.Capabilities & Capabilities.LargeRead) > 0;
            LargeWrite = (responseExt.Capabilities & Capabilities.LargeWrite) > 0;
            ServerMaxBufferSize = responseExt.MaxBufferSize;
            MaxMpxCount = Math.Min(responseExt.MaxMpxCount, ClientMaxMpxCount);
            _securityBlob = responseExt.SecurityBlob;
            return ntSMB && rpc && ntStatusCode;
        }

        return false;
    }

    public Task<NTStatus> Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod = AuthenticationMethod.NTLMv2, CancellationToken cancellationToken = default)
    {
        if (!IsConnected) throw new InvalidOperationException("A connection must be successfully established before attempting login");

        var clientCapabilities = Capabilities.NTSMB | Capabilities.RpcRemoteApi | Capabilities.NTStatusCode |
                         Capabilities.NTFind;
        if (Unicode) clientCapabilities |= Capabilities.Unicode;
        if (LargeFiles) clientCapabilities |= Capabilities.LargeFiles;
        if (LargeRead) clientCapabilities |= Capabilities.LargeRead;

        if (_serverChallenge is not null)
        {
            return LoginWithoutExtendedSecurity(domainName, userName, password, authenticationMethod, clientCapabilities, cancellationToken);
        }
        else // if (_securityBlob is not null)
        {
            return LoginWithExtendedSecurity(domainName, userName, password, authenticationMethod, clientCapabilities, cancellationToken);
        }
    }

    private async Task<NTStatus> LoginWithExtendedSecurity(string domainName, string userName, string password, AuthenticationMethod authenticationMethod,
        Capabilities clientCapabilities, CancellationToken cancellationToken)
    {
        Debug.Assert(_securityBlob is not null);

        NtlmAuthenticationClient authenticationClient = new(domainName, userName, password, null, authenticationMethod);
        var negotiateMessage = authenticationClient.InitializeSecurityContext(_securityBlob);
        if (negotiateMessage == null) return NTStatus.SEC_E_INVALID_TOKEN;

        var request = new SessionSetupAndXRequestExtended
        {
            MaxBufferSize = ClientMaxBufferSize,
            MaxMpxCount = MaxMpxCount,
            Capabilities = clientCapabilities,
            SecurityBlob = negotiateMessage
        };
        var smbMessage = CreateSmbMessage(request);
        var reply = await TrySendSmbMessage(smbMessage, cancellationToken);

        while (reply is not null &&
               reply.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED &&
               reply.Commands[0] is SessionSetupAndXResponseExtended response)
        {
            HandleSessionSetupMessage(reply);
            var authenticateMessage = authenticationClient.InitializeSecurityContext(response.SecurityBlob);
            if (authenticateMessage is null) return NTStatus.SEC_E_INVALID_TOKEN;

            _userId = reply.Header.UID;
            request = new SessionSetupAndXRequestExtended
            {
                MaxBufferSize = ClientMaxBufferSize,
                MaxMpxCount = MaxMpxCount,
                Capabilities = clientCapabilities,
                SecurityBlob = authenticateMessage
            };
            smbMessage = CreateSmbMessage(request);
            reply = await TrySendSmbMessage(smbMessage, cancellationToken);
        }

        if (reply is not null && reply.Commands[0] is SessionSetupAndXResponseExtended)
        {
            IsLoggedIn = reply.Header.Status == NTStatus.STATUS_SUCCESS;
            return reply.Header.Status;
        }

        return NTStatus.STATUS_INVALID_SMB;
    }

    private async Task<NTStatus> LoginWithoutExtendedSecurity(string domainName, string userName, string password, AuthenticationMethod authenticationMethod,
        Capabilities clientCapabilities, CancellationToken cancellationToken)
    {
        Debug.Assert(_serverChallenge is not null);

        var request = new SessionSetupAndXRequest
        {
            MaxBufferSize = ClientMaxBufferSize,
            MaxMpxCount = MaxMpxCount,
            Capabilities = clientCapabilities,
            AccountName = userName,
            PrimaryDomain = domainName
        };
        var clientChallenge = new byte[8];
        Random.Shared.NextBytes(clientChallenge);
        if (authenticationMethod == AuthenticationMethod.NTLMv1)
        {
            request.OEMPassword = !Unicode && !string.IsNullOrEmpty(password)
                ? NtlmCryptography.ComputeLMv1Response(_serverChallenge, password)
                : [];
            request.UnicodePassword = Unicode && !string.IsNullOrEmpty(password)
                ? NtlmCryptography.ComputeNTLMv1Response(_serverChallenge, password)
                : [];
        }
        else if (authenticationMethod == AuthenticationMethod.NTLMv1ExtendedSessionSecurity)
        {
            // [MS-CIFS] CIFS does not support Extended Session Security because there is no mechanism in CIFS to negotiate Extended Session Security
            throw new ArgumentException("SMB Extended Security must be negotiated in order for NTLMv1 Extended Session Security to be used");
        }
        else // NTLMv2
        {
            // Note: NTLMv2 over non-extended security session setup is not supported under Windows Vista and later which will return STATUS_INVALID_PARAMETER.
            // https://msdn.microsoft.com/en-us/library/ee441701.aspx
            // https://msdn.microsoft.com/en-us/library/cc236700.aspx
            if (Unicode)
            {
                var clientChallengeStructure = new NtlmV2ClientChallenge(DateTime.UtcNow, clientChallenge,
                    AVPairUtils.GetAVPairSequence(domainName, Environment.MachineName));
                var temp = clientChallengeStructure.GetBytesPadded();
                var proofStr =
                    NtlmCryptography.ComputeNTLMv2Proof(_serverChallenge, temp, password, userName, domainName);
                request.UnicodePassword = ByteUtils.Concatenate(proofStr, temp);
                request.OEMPassword = [];
            }
            else
            {
                request.OEMPassword = NtlmCryptography.ComputeLMv2Response(_serverChallenge, clientChallenge, password,
                    userName, domainName);
                request.UnicodePassword = [];
            }
        }

        var smbMessage = CreateSmbMessage(request);
        var reply = await TrySendSmbMessage(smbMessage, cancellationToken);
        if (reply is not null)
        {
            HandleSessionSetupMessage(reply);
            IsLoggedIn = reply.Header.Status == NTStatus.STATUS_SUCCESS;
            return reply.Header.Status;
        }

        return NTStatus.STATUS_INVALID_SMB;
    }

    private void HandleSessionSetupMessage(Smb1Message message)
    {
        Smb1Command? sessionSetup = message.Commands.Find(x => x.CommandName == CommandName.SMB_COM_SESSION_SETUP_ANDX);
        if (sessionSetup is null) return;

#pragma warning disable S1871 // Two branches in a conditional structure should not have exactly the same implementation
        switch (sessionSetup)
        {
            case SessionSetupAndXRequest command when !string.IsNullOrEmpty(command.NativeOS):
                NativeOs = command.NativeOS;
                NativeLM = command.NativeLanMan;
                break;
            case SessionSetupAndXRequestExtended command when !string.IsNullOrEmpty(command.NativeOS):
                NativeOs = command.NativeOS;
                NativeLM = command.NativeLanMan;
                break;
            case SessionSetupAndXResponse command when !string.IsNullOrEmpty(command.NativeOS):
                NativeOs = command.NativeOS;
                NativeLM = command.NativeLanMan;
                break;
            case SessionSetupAndXResponseExtended command when !string.IsNullOrEmpty(command.NativeOS):
                NativeOs = command.NativeOS;
                NativeLM = command.NativeLanMan;
                break;
        }
#pragma warning restore S1871 // Two branches in a conditional structure should not have exactly the same implementation
    }

    public async Task<NTStatus> Logoff(CancellationToken cancellationToken = default)
    {
        if (!IsConnected) throw new InvalidOperationException("A login session must be successfully established before attempting logoff");

        var request = new LogoffAndXRequest();
        var smbMessage = CreateSmbMessage(request);
        var reply = await TrySendSmbMessage(smbMessage, cancellationToken);

        if (reply is not null)
        {
            IsLoggedIn = reply.Header.Status != NTStatus.STATUS_SUCCESS;
            return reply.Header.Status;
        }

        return NTStatus.STATUS_INVALID_SMB;
    }


    private Smb1Message CreateSmbMessage(Smb1Command command, ushort treeId = 0)
    {
        Smb1Message message = new();
        message.Header.UnicodeFlag = Unicode;
        message.Header.ExtendedSecurityFlag = ForceExtendedSecurity;
        message.Header.Flags2 |= HeaderFlags2.LongNamesAllowed | HeaderFlags2.LongNameUsed | HeaderFlags2.NTStatusCode;
        message.Header.UID = _userId;
        message.Header.TID = treeId;
        message.Commands.Add(command);

        return message;
    }

    private async Task<Smb1Message?> TrySendSmbMessage(Smb1Message message, CancellationToken cancellationToken)
    {
        var trailer = message.GetBytes();
        var packet = new SessionMessagePacket(trailer);
        var reply = await TrySendNetbiosSessionPacket(packet, cancellationToken);
        if (reply is null) return null;

        return Smb1Message.GetSMB1Message(reply.Trailer);
    }

}