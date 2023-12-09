using System;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation;

/// <summary>
///     Default implementation of <see cref="IClientDataDecoder" />.
/// </summary>
public class DefaultClientDataDecoder : IClientDataDecoder
{
    /// <summary>
    ///     Constructs <see cref="DefaultClientDataDecoder" />
    /// </summary>
    /// <param name="safeJsonSerializer">Safe (exceptionless) JSON serializer.</param>
    /// <param name="tokenBindingStatusSerializer">Serializer for the <see cref="TokenBindingStatus" /> enum.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultClientDataDecoder(
        ISafeJsonSerializer safeJsonSerializer,
        IEnumMemberAttributeSerializer<TokenBindingStatus> tokenBindingStatusSerializer,
        ILogger<DefaultClientDataDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(safeJsonSerializer);
        ArgumentNullException.ThrowIfNull(tokenBindingStatusSerializer);
        ArgumentNullException.ThrowIfNull(logger);
        SafeJsonSerializer = safeJsonSerializer;
        TokenBindingStatusSerializer = tokenBindingStatusSerializer;
        Logger = logger;
    }

    /// <summary>
    ///     Safe (exceptionless) JSON serializer.
    /// </summary>
    protected ISafeJsonSerializer SafeJsonSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="TokenBindingStatus" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<TokenBindingStatus> TokenBindingStatusSerializer { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultClientDataDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<CollectedClientData> Decode(string jsonText)
    {
        var clientDataResult = SafeJsonSerializer.DeserializeNonNullable<CollectedClientDataJson>(jsonText);
        if (clientDataResult.HasError)
        {
            Logger.FailedToDeserializeClientData();
            return Result<CollectedClientData>.Fail();
        }

        var clientData = clientDataResult.Ok;
        if (string.IsNullOrEmpty(clientData.Type))
        {
            Logger.ClientDataTypeIsNullOrEmpty();
            return Result<CollectedClientData>.Fail();
        }

        if (string.IsNullOrEmpty(clientData.Challenge))
        {
            Logger.ClientDataChallengeIsNullOrEmpty();
            return Result<CollectedClientData>.Fail();
        }

        if (string.IsNullOrEmpty(clientData.Origin))
        {
            Logger.ClientDataOriginIsNullOrEmpty();
            return Result<CollectedClientData>.Fail();
        }

        TokenBinding? tokenBinding = null;
        if (clientData.TokenBinding is not null)
        {
            var tokenBindingResult = ParseTokenBinding(clientData.TokenBinding);
            if (tokenBindingResult.HasError)
            {
                Logger.FailedToParseTokenBinding();
                return Result<CollectedClientData>.Fail();
            }

            tokenBinding = tokenBindingResult.Ok;
        }

        var result = new CollectedClientData(
            clientData.Type,
            clientData.Challenge,
            clientData.Origin,
            clientData.TopOrigin,
            clientData.CrossOrigin,
            tokenBinding);

        return Result<CollectedClientData>.Success(result);
    }

    private Result<TokenBinding> ParseTokenBinding(TokenBindingJson tokenBinding)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (tokenBinding is null)
        {
            return Result<TokenBinding>.Fail();
        }

        if (string.IsNullOrEmpty(tokenBinding.Status))
        {
            return Result<TokenBinding>.Fail();
        }

        if (!TokenBindingStatusSerializer.TryDeserialize(tokenBinding.Status, out var tokenBindingStatus))
        {
            Logger.InvalidTokenBindingStatus();
            return Result<TokenBinding>.Fail();
        }

        byte[]? id = null;
        if (tokenBinding.Id is not null && !Base64Url.TryDecode(tokenBinding.Id, out id))
        {
            return Result<TokenBinding>.Fail();
        }

        if (tokenBindingStatus.Value == TokenBindingStatus.Present && id is null)
        {
            Logger.TokenBindingIdIsNullOrEmpty();
            return Result<TokenBinding>.Fail();
        }

        var result = new TokenBinding(tokenBindingStatus.Value, id);
        return Result<TokenBinding>.Success(result);
    }
}

/// <summary>
///     Extension methods for logging the 'clientData' decoder.
/// </summary>
public static partial class DefaultClientDataDecoderLoggingExtensions
{
    /// <summary>
    ///     Failed to deserialize 'clientData'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to deserialize 'clientData'")]
    public static partial void FailedToDeserializeClientData(this ILogger logger);

    /// <summary>
    ///     'clientData.type' contains an empty string or null
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.type' contains an empty string or null")]
    public static partial void ClientDataTypeIsNullOrEmpty(this ILogger logger);

    /// <summary>
    ///     'clientData.challenge' contains an empty string or null
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.challenge' contains an empty string or null")]
    public static partial void ClientDataChallengeIsNullOrEmpty(this ILogger logger);

    /// <summary>
    ///     'clientData.origin' contains an empty string or null
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.origin' contains an empty string or null")]
    public static partial void ClientDataOriginIsNullOrEmpty(this ILogger logger);

    /// <summary>
    ///     Failed to parse 'clientData.tokenBinding'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to parse 'clientData.tokenBinding'")]
    public static partial void FailedToParseTokenBinding(this ILogger logger);

    /// <summary>
    ///     'clientData.tokenBinding.status' contains an invalid value
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.tokenBinding.status' contains an invalid value")]
    public static partial void InvalidTokenBindingStatus(this ILogger logger);

    /// <summary>
    ///     'clientData.tokenBinding.status' is 'present', 'clientData.tokenBinding.id' must contain a value
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.tokenBinding.status' is 'present', 'clientData.tokenBinding.id' must contain a value")]
    public static partial void TokenBindingIdIsNullOrEmpty(this ILogger logger);
}
