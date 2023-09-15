using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

/// <summary>
///     Information About Public Key Credential
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#iface-authenticatorresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.2. Authenticator Responses (interface AuthenticatorResponse)</a>
///     <br />
///     <a href="https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.2.1. Information About Public Key Credential (interface AuthenticatorAttestationResponse)</a>
/// </remarks>
public class AuthenticatorAttestationResponse
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorAttestationResponse" />.
    /// </summary>
    /// <param name="clientDataJson">
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/webauthn-3/#authenticatorresponse">AuthenticatorResponse</a>,
    ///     contains the <a href="https://www.w3.org/TR/webauthn-3/#clientdatajson-serialization">JSON-compatible serialization</a>
    ///     of the <a href="https://www.w3.org/TR/webauthn-3/#client-data">client data</a>,
    ///     the <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-hash-of-the-serialized-client-data">hash of which</a> is passed to the authenticator by the client
    ///     in its call to the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    /// </param>
    /// <param name="attestationObject">
    ///     This attribute contains an <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">attestation object</a>, which is opaque to, and cryptographically protected
    ///     against tampering by, the client. The <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">attestation object</a> contains both
    ///     <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> and an <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statement</a>.
    ///     The former contains the AAGUID, a unique <a href="https://www.w3.org/TR/webauthn-3/#credential-id">credential ID</a>,
    ///     and the <a href="https://www.w3.org/TR/webauthn-3/#credential-public-key">credential public key</a>.
    ///     The contents of the <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statement</a> are determined by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement-format">attestation statement format</a> used by the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>.
    ///     It also contains any additional information that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party's</a> server requires
    ///     to validate the <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statement</a>, as well as to decode and validate the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> along with the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a>.
    /// </param>
    /// <exception cref="ArgumentNullException">If the <paramref name="clientDataJson" /> or <paramref name="attestationObject" /> parameter is <see langword="null" />.</exception>
    [JsonConstructor]
    public AuthenticatorAttestationResponse(byte[] clientDataJson, byte[] attestationObject)
    {
        ArgumentNullException.ThrowIfNull(clientDataJson);
        ArgumentNullException.ThrowIfNull(attestationObject);
        ClientDataJson = clientDataJson.CreateCopy();
        AttestationObject = attestationObject.CreateCopy();
    }

    /// <summary>
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/webauthn-3/#authenticatorresponse">AuthenticatorResponse</a>,
    ///     contains the <a href="https://www.w3.org/TR/webauthn-3/#clientdatajson-serialization">JSON-compatible serialization</a>
    ///     of the <a href="https://www.w3.org/TR/webauthn-3/#client-data">client data</a>,
    ///     the <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-hash-of-the-serialized-client-data">hash of which</a> is passed to the authenticator by the client
    ///     in its call to the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    /// </summary>
    [Required]
    [JsonPropertyName("clientDataJSON")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] ClientDataJson { get; }

    /// <summary>
    ///     This attribute contains an <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">attestation object</a>, which is opaque to, and cryptographically protected
    ///     against tampering by, the client. The <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">attestation object</a> contains both
    ///     <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> and an <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statement</a>.
    ///     The former contains the AAGUID, a unique <a href="https://www.w3.org/TR/webauthn-3/#credential-id">credential ID</a>,
    ///     and the <a href="https://www.w3.org/TR/webauthn-3/#credential-public-key">credential public key</a>.
    ///     The contents of the <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statement</a> are determined by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement-format">attestation statement format</a> used by the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>.
    ///     It also contains any additional information that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party's</a> server requires
    ///     to validate the <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statement</a>, as well as to decode and validate the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> along with the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a>.
    /// </summary>
    [Required]
    [JsonPropertyName("attestationObject")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] AttestationObject { get; }
}
