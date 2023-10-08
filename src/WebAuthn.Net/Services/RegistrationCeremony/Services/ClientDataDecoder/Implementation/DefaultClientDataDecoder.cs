using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.ClientDataDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.ClientDataDecoder.Implementation;

public class DefaultClientDataDecoder<TContext> : IClientDataDecoder<TContext>
    where TContext : class, IWebAuthnContext
{
    private readonly ILogger<DefaultClientDataDecoder<TContext>> _logger;

    public DefaultClientDataDecoder(ILogger<DefaultClientDataDecoder<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public virtual Task<Result<CollectedClientData>> DecodeAsync(
        TContext context,
        string jsonText,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var deserializedClientData = JsonSerializer.Deserialize<CollectedClientData>(jsonText);
        if (deserializedClientData is null)
        {
            _logger.FailedToDeserializeClientData();
            return Task.FromResult(Result<CollectedClientData>.Fail());
        }

        if (string.IsNullOrEmpty(deserializedClientData.Type))
        {
            _logger.ClientDataTypeIsNullOrEmpty();
            return Task.FromResult(Result<CollectedClientData>.Fail());
        }

        if (string.IsNullOrEmpty(deserializedClientData.Challenge))
        {
            _logger.ClientDataChallengeIsNullOrEmpty();
            return Task.FromResult(Result<CollectedClientData>.Fail());
        }

        if (string.IsNullOrEmpty(deserializedClientData.Origin))
        {
            _logger.ClientDataOriginIsNullOrEmpty();
            return Task.FromResult(Result<CollectedClientData>.Fail());
        }

        return Task.FromResult(Result<CollectedClientData>.Success(deserializedClientData));
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
