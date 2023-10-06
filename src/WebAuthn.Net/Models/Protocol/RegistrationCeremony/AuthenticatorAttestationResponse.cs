using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

/// <summary>
///     Information About Public Key Credential
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-authenticatorresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.2. Authenticator Responses (interface AuthenticatorResponse)</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-authenticatorattestationresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.2.1. Information About Public Key Credential (interface AuthenticatorAttestationResponse)</a>
///     </para>
/// </remarks>
public class AuthenticatorAttestationResponse
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorAttestationResponse" />.
    /// </summary>
    /// <param name="clientDataJson">
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorresponse">AuthenticatorResponse</a>, contains the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a> (see
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation">§6.5 Attestation</a>) passed to the authenticator by the client in order to generate this credential. The exact JSON serialization MUST be preserved, as the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a> has been computed over it.
    /// </param>
    /// <param name="attestationObject">
    ///     This attribute contains an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a>, which is opaque to, and cryptographically protected against tampering by, the client. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a> contains both <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> and an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>. The former contains the AAGUID, a unique <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a>, and the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a>. The contents of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> are determined by the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement-format">attestation statement format</a> used by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>. It also contains any additional information
    ///     that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a> server requires to validate the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>, as well as to decode and
    ///     validate the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> along with the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a>. For more details, see
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation">§6.5 Attestation</a>, <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-generating-an-attestation-object">§6.5.5 Generating an Attestation Object</a>, and
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">Figure 6</a>.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="clientDataJson" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="attestationObject" /> is <see langword="null" /></exception>
    [JsonConstructor]
    public AuthenticatorAttestationResponse(byte[] clientDataJson, byte[] attestationObject)
    {
        ArgumentNullException.ThrowIfNull(clientDataJson);
        ArgumentNullException.ThrowIfNull(attestationObject);
        ClientDataJson = clientDataJson;
        AttestationObject = attestationObject;
    }

    /// <summary>
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorresponse">AuthenticatorResponse</a>, contains the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a> (see
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation">§6.5 Attestation</a>) passed to the authenticator by the client in order to generate this credential. The exact JSON serialization MUST be preserved, as the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a> has been computed over it.
    /// </summary>
    [Required]
    [JsonPropertyName("clientDataJSON")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] ClientDataJson { get; }

    /// <summary>
    ///     This attribute contains an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a>, which is opaque to, and cryptographically protected against tampering by, the client. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a> contains both <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> and an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>. The former contains the AAGUID, a unique <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a>, and the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a>. The contents of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> are determined by the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement-format">attestation statement format</a> used by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>. It also contains any additional information
    ///     that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a> server requires to validate the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>, as well as to decode and
    ///     validate the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> along with the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a>. For more details, see
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation">§6.5 Attestation</a>, <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-generating-an-attestation-object">§6.5.5 Generating an Attestation Object</a>, and
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">Figure 6</a>.
    /// </summary>
    [Required]
    [JsonPropertyName("attestationObject")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] AttestationObject { get; }
}
