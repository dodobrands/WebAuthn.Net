using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;

namespace WebAuthn.Net.Storage.Operations;

public interface IOperationalStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<PublicKeyCredentialDescriptor[]?> GetExistingCredentialsAsync(
        TContext context,
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        CancellationToken cancellationToken);

    Task<string> SaveRegistrationCeremonyAsync(
        TContext context,
        byte[] challenge,
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        PublicKeyCredentialParameters[] pubKeyCredParams,
        uint? timeout,
        PublicKeyCredentialDescriptor[]? excludeCredentials,
        AuthenticatorSelectionCriteria? authenticatorSelection,
        AttestationConveyancePreference? attestation,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken);
}
