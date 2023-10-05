﻿using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Attestation Conveyance Preference Enumeration
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-attestation-convey">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4.7. Attestation Conveyance Preference Enumeration</a>
/// </remarks>
[JsonConverter(typeof(EnumAsStringConverter<AttestationConveyancePreference>))]
public enum AttestationConveyancePreference
{
    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> is not interested in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation">attestation</a>. For example, in order to potentially avoid having to obtain <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-consent">user consent</a> to relay identifying information
    ///     to the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>, or to save a roundtrip to an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-ca">Attestation CA</a> or
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#anonymization-ca">Anonymization CA</a>. If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> generates an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> that is not a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#self-attestation">self attestation</a>, the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> will replace it with a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#none">None</a> attestation statement.
    /// </summary>
    /// <remarks>
    ///     This is the default, and unknown values fall back to the behavior of this value.
    /// </remarks>
    [EnumMember(Value = "none")]
    None = 0,

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> wants to receive a verifiable <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>, but allows the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> to decide how to obtain such an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>. The client MAY replace an authenticator-generated
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> with one generated by an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#anonymization-ca">Anonymization CA</a>, in order to protect the user’s privacy,
    ///     or to assist <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> with attestation verification in a heterogeneous ecosystem.
    /// </summary>
    /// <remarks>
    ///     There is no guarantee that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> will obtain a verifiable <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> in this case. For
    ///     example, in the case that the authenticator employs <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#self-attestation">self attestation</a> and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> passes the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> through unmodified.
    /// </remarks>
    [EnumMember(Value = "indirect")]
    Indirect = 1,

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> wants to receive the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> as generated by the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>.
    /// </summary>
    [EnumMember(Value = "direct")]
    Direct = 2,

    /// <summary>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> wants to receive an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> that may include uniquely identifying
    ///         information. This is intended for controlled deployments within an enterprise where the organization wishes to tie registrations to specific authenticators. User agents MUST NOT provide such an attestation unless the user agent or authenticator configuration permits it
    ///         for the requested <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a>.
    ///     </para>
    ///     <para>
    ///         If permitted, the user agent SHOULD signal to the authenticator (at <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#CreateCred-InvokeAuthnrMakeCred">invocation time</a>) that enterprise attestation is requested, and convey the resulting
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-attestedcredentialdata-aaguid">AAGUID</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>, unaltered, to the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>.
    ///     </para>
    /// </summary>
    [EnumMember(Value = "enterprise")]
    Enterprise = 3
}
