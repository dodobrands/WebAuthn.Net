using System;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation;

public class DefaultClientDataDecoder : IClientDataDecoder
{
    private readonly ILogger<DefaultClientDataDecoder> _logger;

    public DefaultClientDataDecoder(ILogger<DefaultClientDataDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<CollectedClientData> Decode(string jsonText)
    {
        var deserializedClientData = JsonSerializer.Deserialize<CollectedClientData>(jsonText);
        if (deserializedClientData is null)
        {
            _logger.FailedToDeserializeClientData();
            return Result<CollectedClientData>.Fail();
        }

        if (string.IsNullOrEmpty(deserializedClientData.Type))
        {
            _logger.ClientDataTypeIsNullOrEmpty();
            return Result<CollectedClientData>.Fail();
        }

        if (string.IsNullOrEmpty(deserializedClientData.Challenge))
        {
            _logger.ClientDataChallengeIsNullOrEmpty();
            return Result<CollectedClientData>.Fail();
        }

        if (string.IsNullOrEmpty(deserializedClientData.Origin))
        {
            _logger.ClientDataOriginIsNullOrEmpty();
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

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.type' contains an empty string or null")]
    public static partial void ClientDataTypeIsNullOrEmpty(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.challenge' contains an empty string or null")]
    public static partial void ClientDataChallengeIsNullOrEmpty(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.origin' contains an empty string or null")]
    public static partial void ClientDataOriginIsNullOrEmpty(this ILogger logger);
}
