using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.Assertion;

/// <summary>
///     Web Authentication Assertion
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#iface-authenticatorresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.2. Authenticator Responses (interface AuthenticatorResponse)</a>
///     <br />
///     <a href="https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.2.2. Web Authentication Assertion (interface AuthenticatorAssertionResponse)</a>
/// </remarks>
public class AuthenticatorAssertionResponse
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorAssertionResponse" />.
    /// </summary>
    /// <param name="clientDataJson">
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/webauthn-3/#authenticatorresponse">AuthenticatorResponse</a>,
    ///     contains the <a href="https://www.w3.org/TR/webauthn-3/#clientdatajson-serialization">JSON-compatible serialization</a>
    ///     of the <a href="https://www.w3.org/TR/webauthn-3/#client-data">client data</a> passed to the authenticator by the client in order to generate this assertion.
    ///     The exact JSON serialization must be preserved, as
    ///     the <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a>
    ///     has been computed over it.
    /// </param>
    /// <param name="authenticatorData">This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> returned by the authenticator.</param>
    /// <param name="signature">This attribute contains the raw signature returned from the authenticator.</param>
    /// <param name="userHandle">
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> returned from the authenticator,
    ///     or null if the authenticator did not return a <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a>.
    /// </param>
    /// <exception cref="ArgumentNullException">If one of the parameters <paramref name="clientDataJson" />, <paramref name="authenticatorData" />, or <paramref name="signature" /> is <see langword="null" />.</exception>
    public AuthenticatorAssertionResponse(byte[] clientDataJson, byte[] authenticatorData, byte[] signature, byte[]? userHandle)
    {
        ArgumentNullException.ThrowIfNull(clientDataJson);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        ArgumentNullException.ThrowIfNull(signature);
        ClientDataJson = clientDataJson.CreateCopy();
        AuthenticatorData = authenticatorData.CreateCopy();
        Signature = signature.CreateCopy();
        if (userHandle is not null)
        {
            UserHandle = userHandle.CreateCopy();
        }
    }

    /// <summary>
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/webauthn-3/#authenticatorresponse">AuthenticatorResponse</a>,
    ///     contains the <a href="https://www.w3.org/TR/webauthn-3/#clientdatajson-serialization">JSON-compatible serialization</a>
    ///     of the <a href="https://www.w3.org/TR/webauthn-3/#client-data">client data</a> passed to the authenticator by the client in order to generate this assertion.
    ///     The exact JSON serialization must be preserved, as
    ///     the <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a>
    ///     has been computed over it.
    /// </summary>
    [Required]
    [JsonPropertyName("clientDataJSON")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] ClientDataJson { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> returned by the authenticator.
    /// </summary>
    [Required]
    [JsonPropertyName("authenticatorData")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] AuthenticatorData { get; }

    /// <summary>
    ///     This attribute contains the raw signature returned from the authenticator.
    /// </summary>
    [Required]
    [JsonPropertyName("signature")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] Signature { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> returned from the authenticator,
    ///     or null if the authenticator did not return a <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a>.
    /// </summary>
    [Required]
    [JsonPropertyName("userHandle")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[]? UserHandle { get; }
}
