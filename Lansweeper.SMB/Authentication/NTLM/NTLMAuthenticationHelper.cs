using System.Security.Cryptography;
using Lansweeper.Smb.Authentication.GSSAPI.SPNEGO;
using Lansweeper.Smb.Authentication.GSSAPI;
using Lansweeper.Smb.Enums;
using Lansweeper.Smb.Utilities;

namespace Lansweeper.Smb.Authentication.NTLM;

public static class NtlmAuthenticationHelper
{
    public static byte[]? GetNegotiateMessage(byte[] securityBlob, string? domainName, AuthenticationMethod authenticationMethod)
    {
        bool flag = false;

        if (securityBlob.Length != 0)
        {
            try
            {
                var token = SimpleProtectedNegotiationToken.ReadToken(securityBlob, serverInitiatedNegotiation: true);
                if (token is not SimpleProtectedNegotiationTokenInit simpleProtectedNegotiationTokenInit
                    || !ContainsMechanism(simpleProtectedNegotiationTokenInit, GssIdentifiers.NTLMSSPIdentifier))
                {
                    return null;
                }
            }
            catch
            {
                return null;
            }

            flag = true;
        }

        NegotiateMessage negotiateMessage = new()
        {
            NegotiateFlags = NegotiateFlags.UnicodeEncoding | NegotiateFlags.OEMEncoding | NegotiateFlags.Sign | NegotiateFlags.NTLMSessionSecurity |
                             NegotiateFlags.WorkstationNameSupplied | NegotiateFlags.AlwaysSign | NegotiateFlags.Version |
                             NegotiateFlags.Use128BitEncryption | NegotiateFlags.KeyExchange | NegotiateFlags.Use56BitEncryption
        };
        if (!string.IsNullOrEmpty(domainName))
        {
            negotiateMessage.DomainName = domainName;
            negotiateMessage.NegotiateFlags |= NegotiateFlags.DomainNameSupplied;
        }

        if (authenticationMethod == AuthenticationMethod.NTLMv1)
        {
            negotiateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
        }
        else
        {
            negotiateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
        }

        negotiateMessage.Version = NtlmVersion.Server2003;
        negotiateMessage.Workstation = Environment.MachineName;
        if (flag)
        {
            SimpleProtectedNegotiationTokenInit simpleProtectedNegotiationTokenInit2 = new()
            {
                MechanismTypeList = []
            };
            simpleProtectedNegotiationTokenInit2.MechanismTypeList.Add(GssIdentifiers.NTLMSSPIdentifier);
            simpleProtectedNegotiationTokenInit2.MechanismToken = negotiateMessage.GetBytes();
            return simpleProtectedNegotiationTokenInit2.GetBytes(includeHeader: true);
        }

        return negotiateMessage.GetBytes();
    }

    public static byte[] GetNegotiateMessage(string domainName, string userName, string password,
        AuthenticationMethod authenticationMethod)
    {
        var negotiateMessage = new NegotiateMessage();
        negotiateMessage.NegotiateFlags = NegotiateFlags.UnicodeEncoding |
                                          NegotiateFlags.OEMEncoding |
                                          NegotiateFlags.Sign |
                                          NegotiateFlags.NTLMSessionSecurity |
                                          NegotiateFlags.DomainNameSupplied |
                                          NegotiateFlags.WorkstationNameSupplied |
                                          NegotiateFlags.AlwaysSign |
                                          NegotiateFlags.Version |
                                          NegotiateFlags.Use128BitEncryption |
                                          NegotiateFlags.Use56BitEncryption;

        if (!(userName == string.Empty && password == string.Empty))
            negotiateMessage.NegotiateFlags |= NegotiateFlags.KeyExchange;

        if (authenticationMethod == AuthenticationMethod.NTLMv1)
            negotiateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
        else
            negotiateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;

        negotiateMessage.Version = NtlmVersion.Server2003;
        negotiateMessage.DomainName = domainName;
        negotiateMessage.Workstation = Environment.MachineName;
        return negotiateMessage.GetBytes();
    }

    public static byte[]? GetAuthenticateMessage(byte[] negotiateMessageBytes, byte[] challengeMessageBytes,
        string domainName, string userName, string password, string? spn, AuthenticationMethod authenticationMethod,
        out byte[]? sessionKey)
    {
        sessionKey = null;

        var challengeMessage = GetChallengeMessage(challengeMessageBytes);
        if (challengeMessage is null) return null;

        var time = DateTime.UtcNow;
        var clientChallenge = new byte[8];
        Random.Shared.NextBytes(clientChallenge);

        var authenticateMessage = new AuthenticateMessage();
        // https://msdn.microsoft.com/en-us/library/cc236676.aspx
        authenticateMessage.NegotiateFlags = NegotiateFlags.Sign |
                                             NegotiateFlags.NTLMSessionSecurity |
                                             NegotiateFlags.AlwaysSign |
                                             NegotiateFlags.Version |
                                             NegotiateFlags.Use128BitEncryption |
                                             NegotiateFlags.Use56BitEncryption;
        if ((challengeMessage.NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
            authenticateMessage.NegotiateFlags |= NegotiateFlags.UnicodeEncoding;
        else
            authenticateMessage.NegotiateFlags |= NegotiateFlags.OEMEncoding;

        if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
            authenticateMessage.NegotiateFlags |= NegotiateFlags.KeyExchange;

        if (authenticationMethod == AuthenticationMethod.NTLMv1)
            authenticateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
        else
            authenticateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;

        if (userName == string.Empty && password == string.Empty)
            authenticateMessage.NegotiateFlags |= NegotiateFlags.Anonymous;

        authenticateMessage.UserName = userName;
        authenticateMessage.DomainName = domainName;
        authenticateMessage.WorkStation = Environment.MachineName;
        byte[] sessionBaseKey;
        byte[] keyExchangeKey;
        if (authenticationMethod == AuthenticationMethod.NTLMv1 ||
            authenticationMethod == AuthenticationMethod.NTLMv1ExtendedSessionSecurity)
        {
            // https://msdn.microsoft.com/en-us/library/cc236699.aspx
            if (userName == string.Empty && password == string.Empty)
            {
                authenticateMessage.LmChallengeResponse = [0];
                authenticateMessage.NtChallengeResponse = [];
            }
            else if (authenticationMethod == AuthenticationMethod.NTLMv1)
            {
                authenticateMessage.LmChallengeResponse =
                    NtlmCryptography.ComputeLMv1Response(challengeMessage.ServerChallenge, password);
                authenticateMessage.NtChallengeResponse =
                    NtlmCryptography.ComputeNTLMv1Response(challengeMessage.ServerChallenge, password);
            }
            else // NTLMv1ExtendedSessionSecurity
            {
                authenticateMessage.LmChallengeResponse = ByteUtils.Concatenate(clientChallenge, new byte[16]);
                authenticateMessage.NtChallengeResponse =
                    NtlmCryptography.ComputeNTLMv1ExtendedSessionSecurityResponse(challengeMessage.ServerChallenge,
                        clientChallenge, password);
            }

            sessionBaseKey = MD4.GetByteHashFromBytes(NtlmCryptography.NTOWFv1(password));
            var lmowf = NtlmCryptography.LMOWFv1(password);
            keyExchangeKey = NtlmCryptography.KXKey(sessionBaseKey, authenticateMessage.NegotiateFlags,
                authenticateMessage.LmChallengeResponse, challengeMessage.ServerChallenge, lmowf);
        }
        else // NTLMv2
        {
            // https://msdn.microsoft.com/en-us/library/cc236700.aspx
            var clientChallengeStructure =
                new NtlmV2ClientChallenge(time, clientChallenge, challengeMessage.TargetInfo, spn);
            var clientChallengeStructurePadded = clientChallengeStructure.GetBytesPadded();
            var ntProofStr = NtlmCryptography.ComputeNTLMv2Proof(challengeMessage.ServerChallenge,
                clientChallengeStructurePadded, password, userName, domainName);
            if (userName == string.Empty && password == string.Empty)
            {
                authenticateMessage.LmChallengeResponse = new byte[1];
                authenticateMessage.NtChallengeResponse = [];
            }
            else
            {
                authenticateMessage.LmChallengeResponse = NtlmCryptography.ComputeLMv2Response(
                    challengeMessage.ServerChallenge, clientChallenge, password, userName, challengeMessage.TargetName);
                authenticateMessage.NtChallengeResponse =
                    ByteUtils.Concatenate(ntProofStr, clientChallengeStructurePadded);
            }

            var responseKeyNT = NtlmCryptography.NTOWFv2(password, userName, domainName);
            sessionBaseKey = HMACMD5.HashData(responseKeyNT,ntProofStr);
            keyExchangeKey = sessionBaseKey;
        }

        authenticateMessage.Version = NtlmVersion.Server2003;

        // https://msdn.microsoft.com/en-us/library/cc236676.aspx
        if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
        {
            sessionKey = new byte[16];
            Random.Shared.NextBytes(sessionKey);
            authenticateMessage.EncryptedRandomSessionKey = RC4.Encrypt(keyExchangeKey, sessionKey);
        }
        else
        {
            sessionKey = keyExchangeKey;
        }

        authenticateMessage.CalculateMIC(sessionKey, negotiateMessageBytes, challengeMessageBytes);
        return authenticateMessage.GetBytes();
    }

    public static ChallengeMessage? GetChallengeMessage(byte[] messageBytes)
    {
        if (AuthenticationMessageUtils.IsSignatureValid(messageBytes))
        {
            var messageType = AuthenticationMessageUtils.GetMessageType(messageBytes);
            if (messageType == MessageTypeName.Challenge)
                try
                {
                    return new ChallengeMessage(messageBytes);
                }
                catch
                {
                    return null;
                }
        }

        return null;
    }

    internal static bool ContainsMechanism(SimpleProtectedNegotiationTokenInit token, byte[] mechanismIdentifier)
    {
        if (token.MechanismTypeList is null) return false;

        return token.MechanismTypeList.Exists(mechanism => ByteUtils.AreByteArraysEqual(mechanism, mechanismIdentifier));
    }
}