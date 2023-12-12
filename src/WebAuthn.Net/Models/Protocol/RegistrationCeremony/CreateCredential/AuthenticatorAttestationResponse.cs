using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;

/// <summary>
///     Information about Public Key Credential
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-authenticatorattestationresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.2.1. Information About Public Key Credential (interface AuthenticatorAttestationResponse)</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-authenticatorresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.2. Authenticator Responses (interface AuthenticatorResponse)</a>
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
    /// <param name="authenticatorData">MUST be set to the output of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getauthenticatordata">getAuthenticatorData()</a>.</param>
    /// <param name="transports">MUST be set to the output of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a>.</param>
    /// <param name="publicKey">MUST be set to the output of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickey">getPublicKey()</a>.</param>
    /// <param name="publicKeyAlgorithm">MUST be set to the output of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickeyalgorithm">getPublicKeyAlgorithm()</a>.</param>
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
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="transports" /> array contains a value not defined in <see cref="AuthenticatorTransport" /></exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="publicKeyAlgorithm" /> contains a value that is not defined in <see cref="CoseAlgorithm" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="attestationObject" /> is <see langword="null" /></exception>
    public AuthenticatorAttestationResponse(
        byte[] clientDataJson,
        byte[]? authenticatorData,
        AuthenticatorTransport[]? transports,
        byte[]? publicKey,
        CoseAlgorithm? publicKeyAlgorithm,
        byte[] attestationObject)
    {
        // clientDataJson
        ArgumentNullException.ThrowIfNull(clientDataJson);
        ClientDataJson = clientDataJson;

        // authenticatorData
        AuthenticatorData = authenticatorData;

        // transports
        if (transports is not null)
        {
            foreach (var transport in transports)
            {
                if (!Enum.IsDefined(typeof(AuthenticatorTransport), transport))
                {
                    throw new InvalidEnumArgumentException(nameof(transports), (int) transport, typeof(AuthenticatorTransport));
                }
            }

            Transports = transports;
        }

        // publicKey
        PublicKey = publicKey;

        // publicKeyAlgorithm
        if (publicKeyAlgorithm.HasValue)
        {
            if (!Enum.IsDefined(typeof(CoseAlgorithm), publicKeyAlgorithm.Value))
            {
                throw new InvalidEnumArgumentException(nameof(publicKeyAlgorithm), (int) publicKeyAlgorithm.Value, typeof(CoseAlgorithm));
            }

            PublicKeyAlgorithm = publicKeyAlgorithm.Value;
        }

        // authenticatorData
        ArgumentNullException.ThrowIfNull(attestationObject);
        AttestationObject = attestationObject;
    }

    /// <summary>
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorresponse">AuthenticatorResponse</a>, contains the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a> (see
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation">§6.5 Attestation</a>) passed to the authenticator by the client in order to generate this credential. The exact JSON serialization MUST be preserved, as the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a> has been computed over it.
    /// </summary>
    public byte[] ClientDataJson { get; }

    /// <summary>
    ///     MUST be set to the output of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getauthenticatordata">getAuthenticatorData()</a>.
    /// </summary>
    /// <remarks>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickey">getAuthenticatorData()</a> function was only introduced in level two of this specification.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD use feature detection before utilizing this function by testing the 'getAuthenticatorData' value in 'AuthenticatorAttestationResponse.prototype'.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> that require this function to exist may not interoperate with older user-agents.
    /// </remarks>
    public byte[]? AuthenticatorData { get; }

    /// <summary>
    ///     MUST be set to the output of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a>.
    /// </summary>
    /// <remarks>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> function was only introduced in level two of this specification.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD use feature detection before utilizing this function by testing the 'getTransports' value in 'AuthenticatorAttestationResponse.prototype'.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> that require this function to exist may not interoperate with older user-agents.
    /// </remarks>
    public AuthenticatorTransport[]? Transports { get; }

    /// <summary>
    ///     MUST be set to the output of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickey">getPublicKey()</a>.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickey">getPublicKey()</a> function was only introduced in level two of this specification.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD use feature detection before utilizing this function by testing the 'getPublicKey' value in 'AuthenticatorAttestationResponse.prototype'.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> that require this function to exist may not interoperate with older user-agents.
    ///     </para>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickey">getPublicKey()</a> operation thus returns the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a>
    ///         as a <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7">SubjectPublicKeyInfo</a>. This ArrayBuffer can, for example, be passed to Java's
    ///         <a href="https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/spec/X509EncodedKeySpec.html">java.security.spec.X509EncodedKeySpec</a>, .NET's
    ///         <a href="https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdsa.importsubjectpublickeyinfo">System.Security.Cryptography.ECDsa.ImportSubjectPublicKeyInfo</a>, or Go's
    ///         <a href="https://pkg.go.dev/crypto/x509#ParsePKIXPublicKey">crypto/x509.ParsePKIXPublicKey</a>.
    ///     </para>
    ///     <para>
    ///         A <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7">SubjectPublicKeyInfo</a> does not include information about the signing algorithm (for example, which hash function to use) that is included in the COSE public key. To provide this,
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickeyalgorithm">getPublicKeyAlgorithm()</a> returns the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a>.
    ///     </para>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponsejson-publickey">publicKey</a> field will be missing if
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptionsjson-pubkeycredparams">pubKeyCredParams</a> was used to negotiate a public-key algorithm that the user agent doesn't understand. (See section
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-public-key-easy">§5.2.1.1 "Easily accessing credential data"</a> for a list of which algorithms user agents must support). If using such an algorithm then the public key must be parsed directly from
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponsejson-attestationobject">attestationObject</a> or
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponsejson-authenticatordata">authenticatorData</a>.
    ///     </para>
    /// </remarks>
    public byte[]? PublicKey { get; }

    /// <summary>
    ///     MUST be set to the output of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickeyalgorithm">getPublicKeyAlgorithm()</a>.
    /// </summary>
    /// <remarks>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-getpublickeyalgorithm">getPublicKeyAlgorithm()</a> function was only introduced in level two of this specification.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD use feature detection before utilizing this function by testing the 'getPublicKeyAlgorithm' value in 'AuthenticatorAttestationResponse.prototype'.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> that require this function to exist may not interoperate with older user-agents.
    /// </remarks>
    public CoseAlgorithm? PublicKeyAlgorithm { get; }

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
    public byte[] AttestationObject { get; }
}
