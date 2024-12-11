using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.SMB1;
using Lansweeper.Smb.SMB2;
using Microsoft.Extensions.Logging;

public class SmbClientFactory(INameServiceClient nameServiceClient, ILoggerFactory loggerFactory) : ISmbClientFactory
{
    public Smb1Client CreateSmb1Client()
    {
        var logger = loggerFactory.CreateLogger<Smb1Client>();
        return new Smb1Client(nameServiceClient, logger);
    }

    public Smb2Client CreateSmb2Client()
    {
        var logger = loggerFactory.CreateLogger<Smb2Client>();
        return new Smb2Client(nameServiceClient, logger);
    }
}