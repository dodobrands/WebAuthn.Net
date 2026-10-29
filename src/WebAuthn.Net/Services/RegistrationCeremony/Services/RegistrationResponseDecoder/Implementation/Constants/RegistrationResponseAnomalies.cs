using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation.Constants;

/// <summary>
///     The anomalies that <see cref="DefaultRegistrationResponseDecoder" /> reports with a Warning log entry and the
///     <c>webauthn.reg.response.anomalies</c> counter (<see cref="Metrics.IRegistrationCeremonyCounters.IncrementResponseAnomaly" />).
/// </summary>
/// <remarks>
///     The values of the response are chosen by the client, so every anomaly is counted at most once per response, however many values of the response it concerns.
/// </remarks>
public static class RegistrationResponseAnomalies
{
    /// <summary>
    ///     Rejected: 'response.transports' contains more than 100 values. A client reports each transport of the authenticator once, and fewer than ten transports are defined,
    ///     so the response is rejected before any of the values is examined.
    /// </summary>
    public const string TransportsTooManyValues = "transports.too_many_values";

    /// <summary>
    ///     Rejected: 'response.transports' contains a value that is not a member of <see cref="AuthenticatorTransport" /> (for example, a transport defined after this version of the library).
    ///     Relying Parties SHOULD accept and store unknown values (<a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot">WebAuthn Level 3, §5.2.1</a>),
    ///     but the library can store only the members of <see cref="AuthenticatorTransport" /> and doesn't modify the transports reported by the client
    ///     (<a href="https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-transports">§4</a>), so the response is rejected until the library knows the new transport.
    /// </summary>
    public const string TransportsUnknownValue = "transports.unknown_value";

    /// <summary>
    ///     Rejected: 'response.transports' contains a value more than once, although its values are unique
    ///     (<a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot">WebAuthn Level 3, §5.2.1</a>).
    /// </summary>
    public const string TransportsDuplicateValue = "transports.duplicate_value";

    /// <summary>
    ///     Rejected: 'response.attestationObject' encodes more than 512 KiB. The attestation object is decoded from CBOR before anything in it is verified,
    ///     and the largest attestation objects, those with a certificate chain, take less than 10 KB, so the response is rejected before the attestation object is decoded.
    /// </summary>
    public const string AttestationObjectTooLarge = "attestation_object.too_large";

    /// <summary>
    ///     Rejected: 'response.clientDataJSON' encodes more than 512 KiB. The client data is parsed as JSON before anything in it is verified, and the credential record keeps it,
    ///     while a browser sends a few hundred bytes of client data, so the response is rejected before the client data is decoded.
    /// </summary>
    public const string ClientDataJsonTooLarge = "client_data_json.too_large";
}
