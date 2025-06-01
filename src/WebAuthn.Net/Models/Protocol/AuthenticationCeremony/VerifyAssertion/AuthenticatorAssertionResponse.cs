namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;

/// <summary>
///     Web Authentication Assertion (interface AuthenticatorAssertionResponse)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#iface-authenticatorassertionresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - Web Authentication Assertion (interface AuthenticatorAssertionResponse)</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#iface-authenticatorresponse">Web Authentication: An API for accessing Public Key Credentials Level 3 - Authenticator Responses (interface AuthenticatorResponse)</a>
///     </para>
/// </remarks>
public class AuthenticatorAssertionResponse
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorAssertionResponse" />.
    /// </summary>
    /// <param name="clientDataJson">
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/webauthn-3/#authenticatorresponse">AuthenticatorResponse</a>, contains the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a> (see
    ///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">"Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)"</a>) passed to the authenticator by the client in order to generate this assertion. The exact JSON serialization MUST be preserved,
    ///     as the <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a> has been computed over it.
    /// </param>
    /// <param name="authenticatorData">
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> returned by the authenticator. See <a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">"Authenticator Data"</a>.
    /// </param>
    /// <param name="signature">
    ///     This attribute contains the raw signature returned from the authenticator. See <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">"The authenticatorGetAssertion Operation"</a>.
    /// </param>
    /// <param name="userHandle">
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> returned from the authenticator, or null if the authenticator did not return a <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a>. See
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">"The authenticatorGetAssertion Operation"</a>. The authenticator MUST always return a <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> if the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> option used in <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">the authentication ceremony</a> is
    ///     <a href="https://infra.spec.whatwg.org/#list-is-empty">empty</a>, and MAY return one otherwise.
    /// </param>
    public AuthenticatorAssertionResponse(
        byte[] clientDataJson,
        byte[] authenticatorData,
        byte[] signature,
        byte[]? userHandle)
    {
        ClientDataJson = clientDataJson;
        AuthenticatorData = authenticatorData;
        Signature = signature;
        UserHandle = userHandle;
    }

    /// <summary>
    ///     This attribute, inherited from <a href="https://www.w3.org/TR/webauthn-3/#authenticatorresponse">AuthenticatorResponse</a>, contains the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-json-compatible-serialization-of-client-data">JSON-compatible serialization of client data</a> (see
    ///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">"Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)"</a>) passed to the authenticator by the client in order to generate this assertion. The exact JSON serialization MUST be preserved,
    ///     as the <a href="https://www.w3.org/TR/webauthn-3/#collectedclientdata-hash-of-the-serialized-client-data">hash of the serialized client data</a> has been computed over it.
    /// </summary>
    public byte[] ClientDataJson { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> returned by the authenticator. See <a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">"Authenticator Data"</a>.
    /// </summary>
    public byte[] AuthenticatorData { get; }

    /// <summary>
    ///     This attribute contains the raw signature returned from the authenticator. See <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">"The authenticatorGetAssertion Operation"</a>.
    /// </summary>
    public byte[] Signature { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> returned from the authenticator, or null if the authenticator did not return a <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a>. See
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">"The authenticatorGetAssertion Operation"</a>. The authenticator MUST always return a <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> if the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> option used in <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">the authentication ceremony</a> is
    ///     <a href="https://infra.spec.whatwg.org/#list-is-empty">empty</a>, and MAY return one otherwise.
    /// </summary>
    public byte[]? UserHandle { get; }
}
