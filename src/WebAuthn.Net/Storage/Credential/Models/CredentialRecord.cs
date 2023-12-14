using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Storage.Credential.Models;

/// <summary>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">Credential Record</a>
/// </summary>
/// <remarks>
///     <para>
///         In order to implement the algorithms defined in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-rp-operations">§7 WebAuthn Relying Party Operations</a>, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>
///         MUST store some properties of registered <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential sources</a>. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a>
///         <a href="https://infra.spec.whatwg.org/#struct">struct</a> is an abstraction of these properties stored in a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>. A credential record is created during a
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration-ceremony">registration ceremony</a> and used in subsequent <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a>.
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> MAY delete credential records as necessary or when requested by users.
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">Web Authentication: An API for accessing Public Key Credentials Level 3 - §4. Terminology</a>
///     </para>
/// </remarks>
public class CredentialRecord
{
    /// <summary>
    ///     Constructs <see cref="CredentialRecord" />.
    /// </summary>
    /// <param name="type">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-type">type</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.</param>
    /// <param name="id">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">Credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.</param>
    /// <param name="publicKey">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.</param>
    /// <param name="signCount">
    ///     The latest value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-signcount">signature counter</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from any
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ceremony">ceremony</a> using the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </param>
    /// <param name="transports">
    ///     The value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>.
    /// </param>
    /// <param name="uvInitialized">
    ///     A Boolean value indicating whether any <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credential</a> from this
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> has had the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> set.
    /// </param>
    /// <param name="backupEligible">
    ///     The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-be">BE</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was created.
    /// </param>
    /// <param name="backupState">
    ///     The latest value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-bs">BS</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> in the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from any <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ceremony">ceremony</a> using the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </param>
    /// <param name="attestationObject">
    ///     OPTIONAL. The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-attestationobject">attestationObject</a> attribute when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential</a> source was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>. Storing this enables the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> to reference the credential's <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> at a later time.
    /// </param>
    /// <param name="attestationClientDataJson">
    ///     OPTIONAL. The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a> attribute when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>. Storing this in combination with the above
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#abstract-opdef-credential-record-attestationobject">attestationObject</a> <a href="https://infra.spec.whatwg.org/#struct-item">item</a> enables the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> to re-verify the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a> at a later time.
    /// </param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="type" /> contains a value that is not defined in <see cref="PublicKeyCredentialType" /></exception>
    public CredentialRecord(
        PublicKeyCredentialType type,
        byte[] id,
        CredentialPublicKeyRecord publicKey,
        uint signCount,
        AuthenticatorTransport[] transports,
        bool uvInitialized,
        bool backupEligible,
        bool backupState,
        byte[]? attestationObject,
        byte[]? attestationClientDataJson)
    {
        if (!Enum.IsDefined(typeof(PublicKeyCredentialType), type))
        {
            throw new InvalidEnumArgumentException(nameof(type), (int) type, typeof(PublicKeyCredentialType));
        }

        Type = type;
        Id = id;
        PublicKey = publicKey;
        SignCount = signCount;
        Transports = transports;
        UvInitialized = uvInitialized;
        BackupEligible = backupEligible;
        BackupState = backupState;
        AttestationObject = attestationObject;
        AttestationClientDataJSON = attestationClientDataJson;
    }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-type">type</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">Credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public byte[] Id { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public CredentialPublicKeyRecord PublicKey { get; }

    /// <summary>
    ///     The latest value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-signcount">signature counter</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from any
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ceremony">ceremony</a> using the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public uint SignCount { get; }

    /// <summary>
    ///     The value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>.
    /// </summary>
    /// <remarks>
    ///     Modifying or removing <a href="https://infra.spec.whatwg.org/#list-item">items</a> from the value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> could negatively impact user
    ///     experience, or even prevent use of the corresponding credential.
    /// </remarks>
    public AuthenticatorTransport[] Transports { get; }

    /// <summary>
    ///     <para>
    ///         A Boolean value indicating whether any <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credential</a> from this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>
    ///         has had the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> set.
    ///     </para>
    ///     <para>
    ///         When this is <see langword="true" />, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY consider the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a>
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> as an <a href="https://pages.nist.gov/800-63-3/sp800-63-3.html#af">authentication factor</a> in
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a>. For example, a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> might skip a password prompt if
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#abstract-opdef-credential-record-uvinitialized">uvInitialized</a> is <see langword="true" /> and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a>
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> is set, even when <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> was not required.
    ///     </para>
    ///     <para>
    ///         When this is <see langword="false" />, including an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a> where it would be updated to <see langword="true" />, the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> MUST NOT be relied upon as an
    ///         <a href="https://pages.nist.gov/800-63-3/sp800-63-3.html#af">authentication factor</a>. This is because the first time a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> sets the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> to 1, there is not yet any trust relationship established between the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator's</a>
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a>. Therefore, updating <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#abstract-opdef-credential-record-uvinitialized">uvInitialized</a> from
    ///         <see langword="false" /> to <see langword="true" /> SHOULD require authorization by an additional <a href="https://pages.nist.gov/800-63-3/sp800-63-3.html#af">authentication factor</a> equivalent to WebAuthn
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a>.
    ///     </para>
    /// </summary>
    public bool UvInitialized { get; }

    /// <summary>
    ///     The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-be">BE</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was created.
    /// </summary>
    public bool BackupEligible { get; }

    /// <summary>
    ///     The latest value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-bs">BS</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> in the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from any <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ceremony">ceremony</a> using the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public bool BackupState { get; }

    /// <summary>
    ///     OPTIONAL. The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-attestationobject">attestationObject</a> attribute when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential</a> source was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>. Storing this enables the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> to reference the credential's <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> at a later time.
    /// </summary>
    public byte[]? AttestationObject { get; }

    /// <summary>
    ///     OPTIONAL. The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a> attribute when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>. Storing this in combination with the above
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#abstract-opdef-credential-record-attestationobject">attestationObject</a> <a href="https://infra.spec.whatwg.org/#struct-item">item</a> enables the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> to re-verify the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a> at a later time.
    /// </summary>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public byte[]? AttestationClientDataJSON { get; }
}
