using Lansweeper.Smb.Netbios;
using Lansweeper.Smb.SMB1;
using Lansweeper.Smb.SMB2;
using Microsoft.Extensions.DependencyInjection;

namespace Lansweeper.Smb;

public static class Setup
{
    public static IServiceCollection AddSmb(this IServiceCollection services)
    {
        services.AddLogging(); // ensure logging if not yet setup

        services.AddTransient<INameServiceClient, NameServiceClient>();

        services.AddTransient<Smb1Client>();
        services.AddKeyedTransient<ISmbClient>("smb1", (sp,_) => sp.GetRequiredService<Smb1Client>());
        services.AddTransient<Smb2Client>();
        services.AddKeyedTransient<ISmbClient>("smb2", (sp, _) => sp.GetRequiredService<Smb2Client>());
        services.AddTransient<ISmbClientFactory, SmbClientFactory>();

        return services;
    }
}
