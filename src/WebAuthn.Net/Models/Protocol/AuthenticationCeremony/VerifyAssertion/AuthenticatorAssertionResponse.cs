namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;

/// <summary>
///     Web Authentication Assertion (interface AuthenticatorAssertionResponse)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-authenticatorassertionresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.2.2. Web Authentication Assertion (interface AuthenticatorAssertionResponse)</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-authenticatorresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.2. Authenticator Responses (interface AuthenticatorResponse)</a>
///     </para>
/// </remarks>
public class AuthenticatorAssertionResponse
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorAssertionResponse" />.
    /// </summary>
    /// <param name="clientDataJson">
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorresponse">AuthenticatorResponse</a>, contains the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a> (see
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-client-data">§5.8.1 Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)</a>) passed to the authenticator by the client in order to generate this assertion. The exact JSON
    ///     serialization MUST be preserved, as the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a> has been computed over it.
    /// </param>
    /// <param name="authenticatorData">
    ///     This attribute contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> returned by the authenticator. See
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">§6.1 Authenticator Data</a>.
    /// </param>
    /// <param name="signature">
    ///     This attribute contains the raw signature returned from the authenticator. See <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-op-get-assertion">§6.3.3 The authenticatorGetAssertion Operation</a>.
    /// </param>
    /// <param name="userHandle">
    ///     This attribute contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> returned from the authenticator, or <see langword="null" /> if the authenticator did not return a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a>. See <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-op-get-assertion">§6.3.3 The authenticatorGetAssertion Operation</a>. The authenticator MUST always return a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> if the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> option used in the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a> is <a href="https://infra.spec.whatwg.org/#list-is-empty">empty</a>, and MAY return one otherwise.
    /// </param>
    /// <param name="attestationObject">
    ///     This OPTIONAL attribute contains an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a>, if the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> supports attestation in assertions.
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a>, if present, includes an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>. Unlike the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-attestationobject">attestationObject</a> in an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorattestationresponse">AuthenticatorAttestationResponse</a>,
    ///     it does not contain an authData key because the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> is provided directly in an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a> structure. For more details on attestation, see <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation">§6.5 Attestation</a>,
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-in-assertions">§6.5.1 Attestation in assertions</a>, <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-generating-an-attestation-object">§6.5.5 Generating an Attestation Object</a>,
    ///     and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">Figure 6</a>.
    /// </param>
    public AuthenticatorAssertionResponse(
        byte[] clientDataJson,
        byte[] authenticatorData,
        byte[] signature,
        byte[]? userHandle,
        byte[]? attestationObject)
    {
        ClientDataJson = clientDataJson;
        AuthenticatorData = authenticatorData;
        Signature = signature;
        UserHandle = userHandle;
        AttestationObject = attestationObject;
    }

    /// <summary>
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorresponse">AuthenticatorResponse</a>, contains the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a> (see
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-client-data">§5.8.1 Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)</a>) passed to the authenticator by the client in order to generate this assertion. The exact JSON
    ///     serialization MUST be preserved, as the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a> has been computed over it.
    /// </summary>
    public byte[] ClientDataJson { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> returned by the authenticator. See
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">§6.1 Authenticator Data</a>.
    /// </summary>
    public byte[] AuthenticatorData { get; }

    /// <summary>
    ///     This attribute contains the raw signature returned from the authenticator. See <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-op-get-assertion">§6.3.3 The authenticatorGetAssertion Operation</a>.
    /// </summary>
    public byte[] Signature { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> returned from the authenticator, or <see langword="null" /> if the authenticator did not return a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a>. See <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-op-get-assertion">§6.3.3 The authenticatorGetAssertion Operation</a>. The authenticator MUST always return a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> if the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> option used in the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a> is <a href="https://infra.spec.whatwg.org/#list-is-empty">empty</a>, and MAY return one otherwise.
    /// </summary>
    public byte[]? UserHandle { get; }

    /// <summary>
    ///     This OPTIONAL attribute contains an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a>, if the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> supports attestation in assertions.
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a>, if present, includes an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>. Unlike the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-attestationobject">attestationObject</a> in an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorattestationresponse">AuthenticatorAttestationResponse</a>,
    ///     it does not contain an authData key because the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> is provided directly in an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a> structure. For more details on attestation, see <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation">§6.5 Attestation</a>,
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-in-assertions">§6.5.1 Attestation in assertions</a>, <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-generating-an-attestation-object">§6.5.5 Generating an Attestation Object</a>,
    ///     and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">Figure 6</a>.
    /// </summary>
    public byte[]? AttestationObject { get; }
}
