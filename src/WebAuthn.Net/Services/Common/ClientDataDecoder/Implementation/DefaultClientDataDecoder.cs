using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation;

public class DefaultClientDataDecoder : IClientDataDecoder
{
    public DefaultClientDataDecoder(
        IEnumMemberAttributeSerializer<TokenBindingStatus> tokenBindingStatusSerializer,
        ILogger<DefaultClientDataDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(tokenBindingStatusSerializer);
        ArgumentNullException.ThrowIfNull(logger);
        TokenBindingStatusSerializer = tokenBindingStatusSerializer;
        Logger = logger;
    }

    protected IEnumMemberAttributeSerializer<TokenBindingStatus> TokenBindingStatusSerializer { get; }
    protected ILogger<DefaultClientDataDecoder> Logger { get; }

    public Result<CollectedClientData> Decode(string jsonText)
    {
        var clientData = JsonSerializer.Deserialize<CollectedClientDataJson>(jsonText, new JsonSerializerOptions());
        if (clientData is null)
        {
            Logger.FailedToDeserializeClientData();
            return Result<CollectedClientData>.Fail();
        }

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

    protected virtual Result<TokenBinding> ParseTokenBinding(TokenBindingJson tokenBinding)
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

    protected class CollectedClientDataJson
    {
        [JsonConstructor]
        public CollectedClientDataJson(
            string type,
            string challenge,
            string origin,
            string? topOrigin,
            bool? crossOrigin,
            TokenBindingJson? tokenBinding)
        {
            Type = type;
            Challenge = challenge;
            Origin = origin;
            TopOrigin = topOrigin;
            CrossOrigin = crossOrigin;
            TokenBinding = tokenBinding;
        }

        [JsonPropertyName("type")]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        [Required]
        public string Type { get; }

        [JsonPropertyName("challenge")]
        [Required]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public string Challenge { get; }

        [JsonPropertyName("origin")]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        [Required]
        public string Origin { get; }

        [JsonPropertyName("topOrigin")]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        [Required]
        public string? TopOrigin { get; }

        [JsonPropertyName("crossOrigin")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? CrossOrigin { get; }

        [JsonPropertyName("tokenBinding")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public TokenBindingJson? TokenBinding { get; }
    }

    protected class TokenBindingJson
    {
        [JsonConstructor]
        public TokenBindingJson(string status, string? id)
        {
            Status = status;
            Id = id;
        }

        [JsonPropertyName("status")]
        [Required]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public string Status { get; }

        [JsonPropertyName("id")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Id { get; }
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

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.tokenBinding.status' contains an invalid value")]
    public static partial void InvalidTokenBindingStatus(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'clientData.tokenBinding.status' is 'present', 'clientData.tokenBinding.id' must contain a value")]
    public static partial void TokenBindingIdIsNullOrEmpty(this ILogger logger);
}
