using System;
using System.Text.Json;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.ClientData;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation;

public class DefaultClientDataDecoder : IClientDataDecoder
{
    public Result<DecodedCollectedClientData> Decode(byte[] clientDataJson)
    {
        ArgumentNullException.ThrowIfNull(clientDataJson);
        var deserializedClientData = JsonSerializer.Deserialize<DecodedCollectedClientData>(clientDataJson);
        if (deserializedClientData is null)
        {
            return Result<DecodedCollectedClientData>.Failed("Can't deserialize client data");
        }

        return Result<DecodedCollectedClientData>.Success(deserializedClientData);
    }
}
