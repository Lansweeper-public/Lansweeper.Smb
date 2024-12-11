using Lansweeper.Smb.Authentication.GSSAPI;
using Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;
using Lansweeper.Smb.Authentication.NTLM;
using Lansweeper.Smb.Enums;
using System.Diagnostics;

namespace Lansweeper.Smb.Authentication;

public class NtlmAuthenticationClient : IAuthenticationClient
{
    private readonly AuthenticationMethod _authenticationMethod;
    private readonly string _domainName;

    private bool _isNegotiationMessageAcquired;
    private byte[]? _negotiateMessageBytes;
    private readonly string _password;
    private byte[]? _sessionKey;
    private readonly string? _spn;
    private readonly string _userName;

    public NtlmAuthenticationClient(string domainName, string userName, string password, string? spn,
        AuthenticationMethod authenticationMethod)
    {
        _domainName = domainName;
        _userName = userName;
        _password = password;
        _spn = spn;
        _authenticationMethod = authenticationMethod;
    }

    public byte[]? InitializeSecurityContext(byte[] securityBlob)
    {
        if (!_isNegotiationMessageAcquired)
        {
            _isNegotiationMessageAcquired = true;
            return GetNegotiateMessage(securityBlob);
        }

        return GetAuthenticateMessage(securityBlob);
    }

    public virtual byte[]? GetSessionKey()
    {
        return _sessionKey;
    }

    protected virtual byte[]? GetNegotiateMessage(byte[] securityBlob)
    {
        var useGSSAPI = false;
        if (securityBlob.Length > 0)
        {
            try
            {
                var spnegoToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, true) as SimpleProtectedNegotiationTokenInit;
                if (spnegoToken is null || !NtlmAuthenticationHelper.ContainsMechanism(spnegoToken, GssIdentifiers.NTLMSSPIdentifier)) return null;
            }
            catch
            {
                return null;
            }

            useGSSAPI = true;
        }

        _negotiateMessageBytes = NtlmAuthenticationHelper.GetNegotiateMessage(_domainName, _userName, _password, _authenticationMethod);

        if (useGSSAPI)
        {
            var outputToken = new SimpleProtectedNegotiationTokenInit
            {
                MechanismTypeList = [GssIdentifiers.NTLMSSPIdentifier],
                MechanismToken = _negotiateMessageBytes
            };
            return outputToken.GetBytes(true);
        }

        return _negotiateMessageBytes;
    }

    protected virtual byte[]? GetAuthenticateMessage(byte[] securityBlob)
    {
        Debug.Assert(_negotiateMessageBytes is not null, $"Make sure you call {nameof(GetNegotiateMessage)}, before calling this method");

        var useGSSAPI = false;
        SimpleProtectedNegotiationTokenResponse? spnegoToken = null;
        try
        {
            spnegoToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, false) as SimpleProtectedNegotiationTokenResponse;
        }
        catch
        {
            // Ignore
        }

        byte[] challengeMessageBytes;
        if (spnegoToken is null)
        {
            challengeMessageBytes = securityBlob;
        }
        else if(spnegoToken.ResponseToken is not null)
        {
            challengeMessageBytes = spnegoToken.ResponseToken;
            useGSSAPI = true;
        }
        else
        {
            return null;
        }

        var authenticateMessageBytes = NtlmAuthenticationHelper.GetAuthenticateMessage(_negotiateMessageBytes,
            challengeMessageBytes, _domainName, _userName, _password, _spn, _authenticationMethod, out _sessionKey);

        if (useGSSAPI && authenticateMessageBytes is not null)
        {
            var outputToken = new SimpleProtectedNegotiationTokenResponse
            {
                ResponseToken = authenticateMessageBytes
            };
            var mechanismTypeList = new List<byte[]> { GssIdentifiers.NTLMSSPIdentifier };
            var mechListBytes = SimpleProtectedNegotiationTokenInit.GetMechanismTypeListBytes(mechanismTypeList);
            outputToken.MechanismListMIC = NtlmCryptography.ComputeMechListMIC(_sessionKey!, mechListBytes); // sessionKey is not null, when authenticateMessageBytes is not null
            return outputToken.GetBytes();
        }

        return authenticateMessageBytes;
    }
}