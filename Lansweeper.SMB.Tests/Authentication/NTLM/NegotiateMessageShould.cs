using Lansweeper.Smb.Authentication.NTLM;

namespace Lansweeper.SMB.Tests.Authentication.NTLM;

internal class NegotiateMessageShould
{
    [Test]
    public void ConstructPropertiesCorrectlyFromBuffer()
    {
        // no domain, no workstation
        byte[] buffer = [
          0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x97, 0x82, 0x08, 0xe2,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset (0x28) SHOULD be set, but is not --> should still work
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset (0x28) SHOULD be set, but is not --> should still work
          0x0a, 0x00, 0x5a, 0x29, 0x00, 0x00, 0x00, 0x0f
        ];

        NegotiateFlags expectedFlags = NegotiateFlags.UnicodeEncoding | NegotiateFlags.OEMEncoding | NegotiateFlags.TargetNameSupplied // why is TargetNameSupplied set, there is no target name?
            | NegotiateFlags.Sign | NegotiateFlags.LanManagerSessionKey | NegotiateFlags.NTLMSessionSecurity | NegotiateFlags.AlwaysSign
            | NegotiateFlags.ExtendedSessionSecurity | NegotiateFlags.Version | NegotiateFlags.Use128BitEncryption | NegotiateFlags.KeyExchange
            | NegotiateFlags.Use56BitEncryption;

        NegotiateMessage sut = new(buffer);

        sut.Signature.Should().Be("NTLMSSP\0");
        sut.MessageType.Should().Be(MessageTypeName.Negotiate);
        sut.NegotiateFlags.Should().Be(expectedFlags);
        sut.DomainName.Should().BeEmpty();
        sut.Workstation.Should().BeEmpty();
        sut.Version.Should().BeEquivalentTo(new NtlmVersion(10, 0, 10586, 15));
    }

    [Test]
    public void GetBytesCorrectly()
    {
        // no domain, no workstation
        byte[] expectedBytes = [
          0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x97, 0x82, 0x08, 0xe2,
          0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, // offset (0x28) SHOULD be set
          0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, // offset (0x28) SHOULD be set
          0x0a, 0x00, 0x5a, 0x29, 0x00, 0x00, 0x00, 0x0f
        ];

        NegotiateMessage sut = new()
        {
            NegotiateFlags = NegotiateFlags.UnicodeEncoding | NegotiateFlags.OEMEncoding | NegotiateFlags.TargetNameSupplied // why is TargetNameSupplied set, there is no target name?
                | NegotiateFlags.Sign | NegotiateFlags.LanManagerSessionKey | NegotiateFlags.NTLMSessionSecurity | NegotiateFlags.AlwaysSign
                | NegotiateFlags.ExtendedSessionSecurity | NegotiateFlags.Use128BitEncryption | NegotiateFlags.KeyExchange
                | NegotiateFlags.Use56BitEncryption,
            Version = new NtlmVersion(10, 0, 10586, 15)
        };

        byte[] actualBytes = sut.GetBytes();

        actualBytes.Should().Equal(expectedBytes);
    }

    // netbios.pcap, message 22
    [Test]
    public void ConstructPropertiesCorrectlyFromBufferWithDomainAndWorkStation()
    {
        byte[] buffer = [
          0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x08, 0x60,
          0x06, 0x00, 0x06, 0x00, 0x20, 0x00, 0x00, 0x00,
          0x07, 0x00, 0x07, 0x00, 0x26, 0x00, 0x00, 0x00,
          0x4d, 0x53, 0x48, 0x4f, 0x4d, 0x45, 0x44, 0x48,
          0x43, 0x50, 0x50, 0x43, 0x33
        ];

        NegotiateFlags expectedFlags = NegotiateFlags.UnicodeEncoding  | NegotiateFlags.TargetNameSupplied
            | NegotiateFlags.Sign | NegotiateFlags.NTLMSessionSecurity | NegotiateFlags.AlwaysSign | NegotiateFlags.ExtendedSessionSecurity
            | NegotiateFlags.Use128BitEncryption | NegotiateFlags.KeyExchange;

        NegotiateMessage sut = new(buffer);

        sut.Signature.Should().Be("NTLMSSP\0");
        sut.MessageType.Should().Be(MessageTypeName.Negotiate);
        sut.NegotiateFlags.Should().Be(expectedFlags);
        sut.DomainName.Should().Be("MSHOME");
        sut.Workstation.Should().Be("DHCPPC3");
        sut.Version.Should().Be(NtlmVersion.Unset);
    }

    [Test]
    public void GetBytesCorrectlyWithDomainAndWorkStation()
    {
        byte[] expectedBytes = [
          0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x15, 
          0xb2, // slight difference here because the workstation name and domain name flags are set
          0x08, 0x60, 
          0x06, 0x00, 0x06, 0x00, 0x20, 0x00, 0x00, 0x00,
          0x07, 0x00, 0x07, 0x00, 0x26, 0x00, 0x00, 0x00,
          0x4d, 0x53, 0x48, 0x4f, 0x4d, 0x45, 0x44, 0x48,
          0x43, 0x50, 0x50, 0x43, 0x33
        ];

        NegotiateMessage sut = new()
        {
            NegotiateFlags = NegotiateFlags.UnicodeEncoding | NegotiateFlags.TargetNameSupplied
                | NegotiateFlags.Sign | NegotiateFlags.NTLMSessionSecurity | NegotiateFlags.AlwaysSign | NegotiateFlags.ExtendedSessionSecurity
                | NegotiateFlags.Use128BitEncryption | NegotiateFlags.KeyExchange,
            DomainName = "MSHOME",
            Workstation = "DHCPPC3"
        };

        byte[] actualBytes = sut.GetBytes();

        actualBytes.Should().Equal(expectedBytes);
    }
}