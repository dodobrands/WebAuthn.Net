using System;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation.Constants;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder.Implementation;

/// <summary>
///     Default implementation of <see cref="IAuthenticationResponseDecoder" />.
/// </summary>
public class DefaultAuthenticationResponseDecoder : IAuthenticationResponseDecoder
{
    // The authenticator data is decoded (its extensions from CBOR) before the signature over it is verified, so its size is limited first.
    // In an assertion it takes 37 bytes plus the extension outputs, usually well under 1 KB.
    private const int MaxAuthenticatorDataSize = 128 * 1024;

    // the length of the base64url encoding (without padding) of MaxAuthenticatorDataSize bytes: a longer 'authenticatorData' encodes more bytes
    private const int MaxAuthenticatorDataLength = ((MaxAuthenticatorDataSize * 4) + 2) / 3;

    /// <summary>
    ///     Constructs <see cref="DefaultAuthenticationResponseDecoder" />.
    /// </summary>
    /// <param name="authenticatorAttachmentSerializer">Serializer for the <see cref="AuthenticatorAttachment" /> enum.</param>
    /// <param name="publicKeyCredentialTypeSerializer">Serializer for the <see cref="PublicKeyCredentialType" /> enum.</param>
    /// <param name="counters">Counters for authentication ceremony metrics, used to count the anomalies found while decoding the response.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAuthenticationResponseDecoder(
        IEnumMemberAttributeSerializer<AuthenticatorAttachment> authenticatorAttachmentSerializer,
        IEnumMemberAttributeSerializer<PublicKeyCredentialType> publicKeyCredentialTypeSerializer,
        IAuthenticationCeremonyCounters counters,
        ILogger<DefaultAuthenticationResponseDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(authenticatorAttachmentSerializer);
        ArgumentNullException.ThrowIfNull(publicKeyCredentialTypeSerializer);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        AuthenticatorAttachmentSerializer = authenticatorAttachmentSerializer;
        PublicKeyCredentialTypeSerializer = publicKeyCredentialTypeSerializer;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorAttachment" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorAttachment> AuthenticatorAttachmentSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="PublicKeyCredentialType" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<PublicKeyCredentialType> PublicKeyCredentialTypeSerializer { get; }

    /// <summary>
    ///     Counters for authentication ceremony metrics, used to count the anomalies found while decoding the response
    ///     (see <see cref="AuthenticationResponseAnomalies" />).
    /// </summary>
    protected IAuthenticationCeremonyCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAuthenticationResponseDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<AuthenticationResponse> Decode(AuthenticationResponseJSON authenticationResponse)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (authenticationResponse is null)
        {
            return Result<AuthenticationResponse>.Fail();
        }

        // https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson
        // 'id', 'rawId', 'response' and 'type' are required members. The JSON model does not enforce their presence,
        // so a missing (null) or empty member is reported as a decoding failure here instead of being accepted or throwing.
        if (string.IsNullOrEmpty(authenticationResponse.Id))
        {
            return Result<AuthenticationResponse>.Fail();
        }

        if (!Base64Url.TryDecode(authenticationResponse.Id, out var id))
        {
            return Result<AuthenticationResponse>.Fail();
        }

        if (string.IsNullOrEmpty(authenticationResponse.RawId))
        {
            return Result<AuthenticationResponse>.Fail();
        }

        if (!Base64Url.TryDecode(authenticationResponse.RawId, out var rawId))
        {
            return Result<AuthenticationResponse>.Fail();
        }

        var responseResult = DecodeAuthenticatorAssertionResponse(authenticationResponse.Response);
        if (responseResult.HasError)
        {
            return Result<AuthenticationResponse>.Fail();
        }

        var authenticatorAttachmentResult = DecodeAuthenticatorAttachment(authenticationResponse.AuthenticatorAttachment);
        if (authenticatorAttachmentResult.HasError)
        {
            return Result<AuthenticationResponse>.Fail();
        }

        var typeResult = DecodePublicKeyCredentialType(authenticationResponse.Type);
        if (typeResult.HasError)
        {
            return Result<AuthenticationResponse>.Fail();
        }

        var result = new AuthenticationResponse(
            id,
            rawId,
            responseResult.Ok,
            authenticatorAttachmentResult.Ok,
            authenticationResponse.ClientExtensionResults,
            typeResult.Ok);
        return Result<AuthenticationResponse>.Success(result);
    }

    /// <summary>
    ///     Decodes <see cref="AuthenticatorAssertionResponseJSON" /> (<a href="https://www.w3.org/TR/webauthn-3/#iface-authenticatorassertionresponse">AuthenticatorAssertionResponse</a>) from a model suitable for JSON serialization into a typed representation suitable
    ///     for further work.
    /// </summary>
    /// <param name="response"><a href="https://www.w3.org/TR/webauthn-3/#iface-authenticatorassertionresponse">AuthenticatorAssertionResponse</a> model, suitable for serialization into JSON.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AuthenticatorAssertionResponse" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<AuthenticatorAssertionResponse> DecodeAuthenticatorAssertionResponse(AuthenticatorAssertionResponseJSON response)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (response is null)
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        if (string.IsNullOrEmpty(response.ClientDataJson))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        if (!Base64Url.TryDecode(response.ClientDataJson, out var clientDataJson))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        if (string.IsNullOrEmpty(response.AuthenticatorData))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        if (response.AuthenticatorData.Length > MaxAuthenticatorDataLength)
        {
            Logger.AuthenticatorDataTooLarge(response.AuthenticatorData.Length, MaxAuthenticatorDataLength, MaxAuthenticatorDataSize);
            Counters.IncrementResponseAnomaly(AuthenticationResponseAnomalies.AuthenticatorDataTooLarge, false);
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        if (!Base64Url.TryDecode(response.AuthenticatorData, out var authenticatorData))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        if (string.IsNullOrEmpty(response.Signature))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        if (!Base64Url.TryDecode(response.Signature, out var signature))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        byte[]? userHandle = null;
        if (!string.IsNullOrEmpty(response.UserHandle))
        {
            if (!Base64Url.TryDecode(response.UserHandle, out userHandle))
            {
                return Result<AuthenticatorAssertionResponse>.Fail();
            }
        }

        var result = new AuthenticatorAssertionResponse(
            clientDataJson,
            authenticatorData,
            signature,
            userHandle);
        return Result<AuthenticatorAssertionResponse>.Success(result);
    }

    /// <summary>
    ///     Decodes the <see cref="AuthenticatorAttachment" /> enum from string to typed representation.
    /// </summary>
    /// <param name="authenticatorAttachment">String value of the <see cref="AuthenticatorAttachment" /> enum.</param>
    /// <returns>If the decoding was successful, the result contains an <see cref="AuthenticatorAttachment" /> or <see langword="null" />, otherwise, the result indicates that an error occurred during decoding.</returns>
    protected virtual Result<AuthenticatorAttachment?> DecodeAuthenticatorAttachment(string? authenticatorAttachment)
    {
        if (authenticatorAttachment is null)
        {
            return Result<AuthenticatorAttachment?>.Success(null);
        }

        if (!AuthenticatorAttachmentSerializer.TryDeserialize(authenticatorAttachment, out var attachment))
        {
            return Result<AuthenticatorAttachment?>.Fail();
        }

        return Result<AuthenticatorAttachment?>.Success(attachment.Value);
    }

    /// <summary>
    ///     Decodes the <see cref="PublicKeyCredentialType" /> enum from string to typed representation.
    /// </summary>
    /// <param name="type">String value of the <see cref="PublicKeyCredentialType" /> enum.</param>
    /// <returns>If the decoding was successful, the result contains a <see cref="PublicKeyCredentialType" />, otherwise, the result indicates that an error occurred during decoding.</returns>
    protected virtual Result<PublicKeyCredentialType> DecodePublicKeyCredentialType(string type)
    {
        if (string.IsNullOrEmpty(type))
        {
            return Result<PublicKeyCredentialType>.Fail();
        }

        if (!PublicKeyCredentialTypeSerializer.TryDeserialize(type, out var publicKeyCredentialType))
        {
            return Result<PublicKeyCredentialType>.Fail();
        }

        return Result<PublicKeyCredentialType>.Success(publicKeyCredentialType.Value);
    }
}

/// <summary>
///     Extension methods for logging the authentication response decoder.
/// </summary>
public static partial class DefaultAuthenticationResponseDecoderLoggingExtensions
{
    /// <summary>
    ///     The 'response.authenticatorData' of the authentication response is {Length} characters long, which exceeds the maximum of {MaxLength} characters (the base64url encoding of {MaxSize} bytes); the response is rejected
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="length">The length of the base64url-encoded authenticator data of the response.</param>
    /// <param name="maxLength">The maximum length of the base64url-encoded authenticator data that is accepted.</param>
    /// <param name="maxSize">The maximum size of the authenticator data in bytes that is accepted.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'response.authenticatorData' of the authentication response is {Length} characters long, which exceeds the maximum of {MaxLength} characters (the base64url encoding of {MaxSize} bytes); the response is rejected")]
    public static partial void AuthenticatorDataTooLarge(this ILogger logger, int length, int maxLength, int maxSize);
}
