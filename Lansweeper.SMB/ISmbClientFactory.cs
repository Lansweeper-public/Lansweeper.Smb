using Lansweeper.Smb.SMB1;
using Lansweeper.Smb.SMB2;

public interface ISmbClientFactory
{
    Smb1Client CreateSmb1Client();
    Smb2Client CreateSmb2Client();
}