using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.FidoAttestationCertificateInspector;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AuthenticatorDataDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions;

public interface IFidoAttestationCertificateInspector<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<Optional<FidoAttestationCertificateInspectionResult>>> InspectAttestationCertificateAsync(
        TContext context,
        X509Certificate2 attestationCertificate,
        AttestedAuthenticatorData authenticatorData,
        IReadOnlySet<AttestationType> acceptableAttestationTypes,
        CancellationToken cancellationToken);
}
