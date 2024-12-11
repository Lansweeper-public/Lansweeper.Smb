namespace Lansweeper.Smb.Netbios;

/// <summary>
/// NetBIOS Name Service (NBNS) probe result
/// </summary>
public class NbnsProbeResult
{
    public string? ServiceName { get; set; }
    public string? ComputerName { get; set; }
    public string? DomainName { get; set; }
    public string? MacAddress { get; set; }

    public override string ToString()
    {
        return $"MAC: {MacAddress}, NAME: {ComputerName}, DOMAIN: {DomainName}";
    }
}