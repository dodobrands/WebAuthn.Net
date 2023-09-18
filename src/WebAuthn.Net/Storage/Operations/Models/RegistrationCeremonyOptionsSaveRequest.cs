using System;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;

namespace WebAuthn.Net.Storage.Operations.Models;

public class RegistrationCeremonyOptionsSaveRequest
{
    public RegistrationCeremonyOptionsSaveRequest(
        byte[] challenge,
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        PublicKeyCredentialParameters[] pubKeyCredParams,
        uint? timeout,
        PublicKeyCredentialDescriptor[]? excludeCredentials,
        AuthenticatorSelectionCriteria? authenticatorSelection,
        AttestationConveyancePreference? attestation,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt)
    {
        Challenge = challenge;
        Rp = rp;
        User = user;
        PubKeyCredParams = pubKeyCredParams;
        Timeout = timeout;
        ExcludeCredentials = excludeCredentials;
        AuthenticatorSelection = authenticatorSelection;
        Attestation = attestation;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public byte[] Challenge { get; }
    public PublicKeyCredentialRpEntity Rp { get; }
    public PublicKeyCredentialUserEntity User { get; }
    public PublicKeyCredentialParameters[] PubKeyCredParams { get; }
    public uint? Timeout { get; }
    public PublicKeyCredentialDescriptor[]? ExcludeCredentials { get; }
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; }
    public AttestationConveyancePreference? Attestation { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset? ExpiresAt { get; }
}
