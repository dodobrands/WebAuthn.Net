using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;

public class AuthenticatorAttestationResponse
{
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

    public byte[] ClientDataJson { get; }

    public byte[]? AuthenticatorData { get; }

    public AuthenticatorTransport[]? Transports { get; }

    public byte[]? PublicKey { get; }

    public CoseAlgorithm? PublicKeyAlgorithm { get; }

    public byte[] AttestationObject { get; }
}
