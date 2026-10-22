using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation.Constants;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;

/// <summary>
///     Default implementation of <see cref="IRegistrationResponseDecoder" />.
/// </summary>
[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultRegistrationResponseDecoder : IRegistrationResponseDecoder
{
    // the transports are chosen by the client: a response with more of them is rejected before any of them is examined
    // (a client reports each transport of the authenticator once, and fewer than ten transports are defined)
    private const int MaxTransports = 100;

    // a Warning lists at most this many of the unknown transports, each of them truncated to this length (see LogValue.Sanitize)
    private const int MaxListedTransports = 8;
    private const int MaxLoggedTransportLength = 64;

    /// <summary>
    ///     Constructs <see cref="DefaultRegistrationResponseDecoder" />.
    /// </summary>
    /// <param name="authenticatorTransportSerializer">Serializer for the <see cref="AuthenticatorTransport" /> enum.</param>
    /// <param name="authenticatorAttachmentSerializer">Serializer for the <see cref="AuthenticatorAttachment" /> enum.</param>
    /// <param name="publicKeyCredentialTypeSerializer">Serializer for the <see cref="PublicKeyCredentialType" /> enum.</param>
    /// <param name="counters">Counters for registration ceremony metrics, used to count the anomalies found while decoding the response.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultRegistrationResponseDecoder(
        IEnumMemberAttributeSerializer<AuthenticatorTransport> authenticatorTransportSerializer,
        IEnumMemberAttributeSerializer<AuthenticatorAttachment> authenticatorAttachmentSerializer,
        IEnumMemberAttributeSerializer<PublicKeyCredentialType> publicKeyCredentialTypeSerializer,
        IRegistrationCeremonyCounters counters,
        ILogger<DefaultRegistrationResponseDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(authenticatorTransportSerializer);
        ArgumentNullException.ThrowIfNull(authenticatorAttachmentSerializer);
        ArgumentNullException.ThrowIfNull(publicKeyCredentialTypeSerializer);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        AuthenticatorTransportSerializer = authenticatorTransportSerializer;
        AuthenticatorAttachmentSerializer = authenticatorAttachmentSerializer;
        PublicKeyCredentialTypeSerializer = publicKeyCredentialTypeSerializer;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorTransport" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorTransport> AuthenticatorTransportSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorAttachment" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorAttachment> AuthenticatorAttachmentSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="PublicKeyCredentialType" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<PublicKeyCredentialType> PublicKeyCredentialTypeSerializer { get; }

    /// <summary>
    ///     Counters for registration ceremony metrics, used to count the anomalies found while decoding the response
    ///     (see <see cref="RegistrationResponseAnomalies" />).
    /// </summary>
    protected IRegistrationCeremonyCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultRegistrationResponseDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<RegistrationResponse> Decode(RegistrationResponseJSON registrationResponse)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (registrationResponse is null)
        {
            return Result<RegistrationResponse>.Fail();
        }

        // https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson
        // 'id', 'rawId', 'response' and 'type' are required members. The JSON model does not enforce their presence,
        // so a missing (null) or empty member is reported as a decoding failure here instead of throwing.
        if (string.IsNullOrEmpty(registrationResponse.Id))
        {
            return Result<RegistrationResponse>.Fail();
        }

        if (!Base64Url.TryDecode(registrationResponse.Id, out var id))
        {
            return Result<RegistrationResponse>.Fail();
        }

        if (string.IsNullOrEmpty(registrationResponse.RawId))
        {
            return Result<RegistrationResponse>.Fail();
        }

        if (!Base64Url.TryDecode(registrationResponse.RawId, out var rawId))
        {
            return Result<RegistrationResponse>.Fail();
        }

        var responseResult = DecodeAttestationResponse(registrationResponse.Response);
        if (responseResult.HasError)
        {
            return Result<RegistrationResponse>.Fail();
        }

        AuthenticatorAttachment? authenticatorAttachment = null;
        if (registrationResponse.AuthenticatorAttachment is not null)
        {
            if (!AuthenticatorAttachmentSerializer.TryDeserialize(registrationResponse.AuthenticatorAttachment, out var attachment))
            {
                return Result<RegistrationResponse>.Fail();
            }

            authenticatorAttachment = attachment.Value;
        }

        if (string.IsNullOrEmpty(registrationResponse.Type))
        {
            return Result<RegistrationResponse>.Fail();
        }

        if (!PublicKeyCredentialTypeSerializer.TryDeserialize(registrationResponse.Type, out var type))
        {
            return Result<RegistrationResponse>.Fail();
        }

        var result = new RegistrationResponse(
            id,
            rawId,
            responseResult.Ok,
            authenticatorAttachment,
            registrationResponse.ClientExtensionResults,
            type.Value);
        return Result<RegistrationResponse>.Success(result);
    }

    private Result<AuthenticatorAttestationResponse> DecodeAttestationResponse(AuthenticatorAttestationResponseJSON attestationResponseJson)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attestationResponseJson is null)
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        // https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson
        // 'clientDataJSON' and 'attestationObject' are required members.
        if (string.IsNullOrEmpty(attestationResponseJson.ClientDataJson))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        if (!Base64Url.TryDecode(attestationResponseJson.ClientDataJson, out var clientDataJson))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        byte[]? authenticatorData = null;
        if (attestationResponseJson.AuthenticatorData is not null && !Base64Url.TryDecode(attestationResponseJson.AuthenticatorData, out authenticatorData))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        var transportsResult = DecodeTransports(attestationResponseJson.Transports);
        if (transportsResult.HasError)
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        byte[]? publicKey = null;
        if (attestationResponseJson.PublicKey is not null && !Base64Url.TryDecode(attestationResponseJson.PublicKey, out publicKey))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        CoseAlgorithm? publicKeyAlgorithm = null;
        if (attestationResponseJson.PublicKeyAlgorithm.HasValue)
        {
            var castedAlgorithm = (CoseAlgorithm) attestationResponseJson.PublicKeyAlgorithm.Value;
            if (!Enum.IsDefined(castedAlgorithm))
            {
                return Result<AuthenticatorAttestationResponse>.Fail();
            }

            publicKeyAlgorithm = castedAlgorithm;
        }

        if (string.IsNullOrEmpty(attestationResponseJson.AttestationObject))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        if (!Base64Url.TryDecode(attestationResponseJson.AttestationObject, out var attestationObject))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        var result = new AuthenticatorAttestationResponse(
            clientDataJson,
            authenticatorData,
            transportsResult.Ok,
            publicKey,
            publicKeyAlgorithm,
            attestationObject);
        return Result<AuthenticatorAttestationResponse>.Success(result);
    }

    /// <summary>
    ///     Decodes the transports of the response (the value of <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-gettransports">getTransports()</a>) into the transports of the credential record.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The transports are kept exactly as the client reported them: "Modifying or removing items from the value returned from getTransports() could negatively impact user experience,
    ///         or even prevent use of the corresponding credential" (<a href="https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-transports">§4</a>).
    ///         Therefore, a response whose transports can't be kept as they are is rejected:
    ///     </para>
    ///     <list type="bullet">
    ///         <item>
    ///             <description>
    ///                 more than 99 transports - before any of them is examined, because a client reports each transport of the authenticator once, and fewer than ten transports are defined;
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <description>
    ///                 a value that is not a member of <see cref="AuthenticatorTransport" />. Relying Parties SHOULD accept and store unknown values
    ///                 (<a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot">§5.2.1</a>), but the library can store only the members of <see cref="AuthenticatorTransport" />,
    ///                 so such a response is rejected until the library knows the new transport;
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <description>
    ///                 a value that occurs more than once - the values are unique (<a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot">§5.2.1</a>).
    ///             </description>
    ///         </item>
    ///     </list>
    ///     <para>
    ///         Every rejection is reported with a single Warning log entry and counted (see <see cref="RegistrationResponseAnomalies" />).
    ///         The values are chosen by the client, so the entry about the unknown values contains their number and lists at most 8 distinct values.
    ///     </para>
    /// </remarks>
    /// <param name="transports">The values of 'response.transports', or <see langword="null" /> if the response doesn't contain them.</param>
    /// <returns>
    ///     If the decoding was successful, the result contains the transports in the order of the response, or <see langword="null" /> if <paramref name="transports" /> is <see langword="null" />.
    ///     Otherwise, the result indicates that the transports were rejected.
    /// </returns>
    protected virtual Result<AuthenticatorTransport[]?> DecodeTransports(string[]? transports)
    {
        if (transports is null)
        {
            return Result<AuthenticatorTransport[]?>.Success(null);
        }

        if (transports.Length > MaxTransports)
        {
            Logger.TransportsTooManyValues(transports.Length, MaxTransports);
            Counters.IncrementResponseAnomaly(RegistrationResponseAnomalies.TransportsTooManyValues, false);
            return Result<AuthenticatorTransport[]?>.Fail();
        }

        var result = new AuthenticatorTransport[transports.Length];
        var unknownCount = 0;
        var listedUnknownTransports = new List<string?>();
        var hasUnlistedUnknownTransports = false;
        for (var i = 0; i < transports.Length; i++)
        {
            if (AuthenticatorTransportSerializer.TryDeserialize(transports[i], out var transport))
            {
                result[i] = transport.Value;
                continue;
            }

            unknownCount++;
            if (!listedUnknownTransports.Contains(transports[i]))
            {
                if (listedUnknownTransports.Count < MaxListedTransports)
                {
                    listedUnknownTransports.Add(transports[i]);
                }
                else
                {
                    hasUnlistedUnknownTransports = true;
                }
            }
        }

        if (unknownCount > 0)
        {
            Logger.TransportsUnknownValues(unknownCount, DescribeUnknownTransports(listedUnknownTransports, hasUnlistedUnknownTransports));
            Counters.IncrementResponseAnomaly(RegistrationResponseAnomalies.TransportsUnknownValue, false);
            return Result<AuthenticatorTransport[]?>.Fail();
        }

        var duplicateCount = result.Length - result.Distinct().Count();
        if (duplicateCount > 0)
        {
            Logger.TransportsDuplicateValues(duplicateCount);
            Counters.IncrementResponseAnomaly(RegistrationResponseAnomalies.TransportsDuplicateValue, false);
            return Result<AuthenticatorTransport[]?>.Fail();
        }

        return Result<AuthenticatorTransport[]?>.Success(result);
    }

    private static string DescribeUnknownTransports(List<string?> listedUnknownTransports, bool hasUnlistedUnknownTransports)
    {
        // the values are untrusted input: a string is neutralized and truncated, a null element of the array is described as such
        var description = new StringBuilder();
        foreach (var transport in listedUnknownTransports)
        {
            if (description.Length > 0)
            {
                description.Append(", ");
            }

            if (transport is null)
            {
                description.Append("null");
            }
            else
            {
                description.Append('\'').Append(LogValue.Sanitize(transport, MaxLoggedTransportLength)).Append('\'');
            }
        }

        if (hasUnlistedUnknownTransports)
        {
            description.Append(", ...");
        }

        return description.ToString();
    }
}

/// <summary>
///     Extension methods for logging the registration response decoder.
/// </summary>
public static partial class DefaultRegistrationResponseDecoderLoggingExtensions
{
    /// <summary>
    ///     The 'transports' of the registration response contain {Count} values, which exceeds the maximum of {MaxCount}; the response is rejected
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of the transports in the response.</param>
    /// <param name="maxCount">The maximum number of the transports in a response that is accepted.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'transports' of the registration response contain {Count} values, which exceeds the maximum of {MaxCount}; the response is rejected")]
    public static partial void TransportsTooManyValues(this ILogger logger, int count, int maxCount);

    /// <summary>
    ///     The 'transports' of the registration response contain {Count} value(s) unknown to the library: {Values}; the response is rejected
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of the values that are unknown to the library.</param>
    /// <param name="values">
    ///     At most 8 distinct unknown values, separated by commas: a string in quotes (truncated to 64 characters, with every control character replaced by '?'),
    ///     <c>null</c> for a null element of the array. If there are more distinct unknown values, the list ends with ", ...".
    /// </param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'transports' of the registration response contain {Count} value(s) unknown to the library: {Values}; the response is rejected")]
    public static partial void TransportsUnknownValues(this ILogger logger, int count, string values);

    /// <summary>
    ///     The 'transports' of the registration response contain {Count} duplicate value(s); the response is rejected
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of the values that repeat an earlier value.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'transports' of the registration response contain {Count} duplicate value(s); the response is rejected")]
    public static partial void TransportsDuplicateValues(this ILogger logger, int count);
}
