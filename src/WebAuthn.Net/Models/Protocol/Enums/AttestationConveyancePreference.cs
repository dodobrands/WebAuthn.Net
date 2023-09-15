﻿using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Attestation Conveyance Preference Enumeration
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#enum-attestation-convey">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.4.7. Attestation Conveyance Preference Enumeration</a>
/// </remarks>
[JsonConverter(typeof(EnumAsStringConverter<AttestationConveyancePreference>))]
public enum AttestationConveyancePreference
{
    /// <summary>
    ///     This value indicates that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is not interested
    ///     in <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> <a href="https://www.w3.org/TR/webauthn-3/#attestation">attestation</a>.
    ///     For example, in order to potentially avoid having to obtain <a href="https://www.w3.org/TR/webauthn-3/#user-consent">user consent</a>
    ///     to relay identifying information to the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>,
    ///     or to save a roundtrip to an <a href="https://www.w3.org/TR/webauthn-3/#attestation-ca">Attestation CA</a>
    ///     or <a href="https://www.w3.org/TR/webauthn-3/#anonymization-ca">Anonymization CA</a>.
    ///     This is the default value.
    /// </summary>
    [EnumMember(Value = "none")]
    None = 0,

    /// <summary>
    ///     This value indicates that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>
    ///     prefers an <a href="https://www.w3.org/TR/webauthn-3/#attestation">attestation</a> conveyance yielding verifiable
    ///     <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statements</a>, but allows the client to decide how to obtain such attestation statements.
    ///     The client may replace the authenticator-generated <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statements</a>
    ///     with attestation statements generated by an <a href="https://www.w3.org/TR/webauthn-3/#anonymization-ca">Anonymization CA</a>,
    ///     in order to protect the user’s privacy, or to assist Relying Parties with attestation verification in a heterogeneous ecosystem.
    /// </summary>
    [EnumMember(Value = "indirect")]
    Indirect = 1,

    /// <summary>
    ///     This value indicates that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>
    ///     wants to receive the <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statements</a>
    ///     as generated by the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>.
    /// </summary>
    [EnumMember(Value = "direct")]
    Direct = 2,

    /// <summary>
    ///     This value indicates that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>
    ///     wants to receive the <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statements</a>
    ///     that may include uniquely identifying information. This is intended for controlled deployments within an enterprise
    ///     where the organization wishes to tie registrations to specific authenticators.
    ///     User agents must not provide such an attestation unless the user agent or authenticator configuration
    ///     permits it for the requested <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a>.
    ///     If permitted, the user agent should signal to the authenticator (at <a href="https://www.w3.org/TR/webauthn-3/#CreateCred-InvokeAuthnrMakeCred">invocation time</a>)
    ///     that enterprise attestation is requested, and convey the resulting <a href="https://www.w3.org/TR/webauthn-3/#aaguid">AAGUID</a>
    ///     and <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statements</a>, unaltered, to the Relying Party.
    /// </summary>
    [EnumMember(Value = "enterprise")]
    Enterprise = 3
}
