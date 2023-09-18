using System;
using System.Text.Json;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.ClientData.Models;

namespace WebAuthn.Net.Services.ClientData.Implementation;

public class DefaultClientDataService : IClientDataService
{
    public Result<CollectedClientData> GetClientData(byte[] clientData)
    {
        ArgumentNullException.ThrowIfNull(clientData);
        var deserializedClientData = JsonSerializer.Deserialize<CollectedClientData>(clientData);
        if (deserializedClientData is null)
        {
            return new("Can't deserialize client data");
        }

        return new(deserializedClientData);
    }
}
