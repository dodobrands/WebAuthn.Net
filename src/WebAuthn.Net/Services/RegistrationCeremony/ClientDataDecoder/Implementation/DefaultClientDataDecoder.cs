using System;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.ClientDataDecoder.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.ClientDataDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.ClientDataDecoder.Implementation;

public class DefaultClientDataDecoder : IClientDataDecoder
{
    private readonly ILogger<DefaultClientDataDecoder> _logger;

    public DefaultClientDataDecoder(ILogger<DefaultClientDataDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<CollectedClientData> Decode(byte[] clientDataJson)
    {
        ArgumentNullException.ThrowIfNull(clientDataJson);
        var deserializedClientData = JsonSerializer.Deserialize<CollectedClientData>(clientDataJson);
        if (deserializedClientData is null)
        {
            _logger.FailedToDeserializeClientData();
            return Result<CollectedClientData>.Fail();
        }

        return Result<CollectedClientData>.Success(deserializedClientData);
    }
}

public static partial class DefaultClientDataDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to deserialize 'clientData'")]
    public static partial void FailedToDeserializeClientData(this ILogger logger);
}
