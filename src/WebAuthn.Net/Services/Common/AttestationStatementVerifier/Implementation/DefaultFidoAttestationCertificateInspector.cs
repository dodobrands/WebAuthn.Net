using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.FidoAttestationCertificateInspector;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation;

public class DefaultFidoAttestationCertificateInspector<TContext>
    : IFidoAttestationCertificateInspector<TContext>
    where TContext : class, IWebAuthnContext
{
    public DefaultFidoAttestationCertificateInspector(
        IFidoMetadataService<TContext> fidoMetadataService,
        IAsn1Decoder asn1Decoder)
    {
        ArgumentNullException.ThrowIfNull(fidoMetadataService);
        ArgumentNullException.ThrowIfNull(asn1Decoder);
        FidoMetadataService = fidoMetadataService;
        Asn1Decoder = asn1Decoder;
    }

    protected IFidoMetadataService<TContext> FidoMetadataService { get; }
    protected IAsn1Decoder Asn1Decoder { get; }

    public async Task<Result<Optional<FidoAttestationCertificateInspectionResult>>> InspectAttestationCertificateAsync(
        TContext context,
        X509Certificate2 attestationCertificate,
        AttestedAuthenticatorData authenticatorData,
        IReadOnlySet<AttestationType> acceptableAttestationTypes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attestationCertificate is null)
        {
            return Result<Optional<FidoAttestationCertificateInspectionResult>>.Fail();
        }

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (authenticatorData is null)
        {
            return Result<Optional<FidoAttestationCertificateInspectionResult>>.Fail();
        }

        // subject key identifier
        var skiResult = TryGetSubjectKeyIdentifier(attestationCertificate);
        if (skiResult.HasError)
        {
            return Result<Optional<FidoAttestationCertificateInspectionResult>>.Fail();
        }

        if (skiResult.Ok.HasValue)
        {
            var skiInspect = await InspectUsingSkiAsync(context, skiResult.Ok.Value, acceptableAttestationTypes, cancellationToken);
            if (skiInspect.HasError || skiInspect.Ok.HasValue)
            {
                return skiInspect;
            }
        }

        // aaguid in certificate
        var aaguidResult = TryGetAaguid(attestationCertificate);
        if (aaguidResult.HasError)
        {
            return Result<Optional<FidoAttestationCertificateInspectionResult>>.Fail();
        }

        // aa guid from certificate or from authenticator data
        Guid? aaguidToInspect = null;
        if (aaguidResult.Ok.HasValue)
        {
            aaguidToInspect = aaguidResult.Ok.Value;
        }
        else if (authenticatorData.AttestedCredentialData.Aaguid != Guid.Empty)
        {
            aaguidToInspect = authenticatorData.AttestedCredentialData.Aaguid;
        }

        if (aaguidToInspect.HasValue)
        {
            return await InspectUsingAaguidAsync(context, aaguidToInspect.Value, acceptableAttestationTypes, cancellationToken);
        }

        return Result<Optional<FidoAttestationCertificateInspectionResult>>.Success(Optional<FidoAttestationCertificateInspectionResult>.Empty());
    }

    protected virtual async Task<Result<Optional<FidoAttestationCertificateInspectionResult>>> InspectUsingSkiAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        IReadOnlySet<AttestationType> acceptableAttestationTypes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadata = await FidoMetadataService.FindMetadataBySubjectKeyIdentifierAsync(
            context,
            subjectKeyIdentifier,
            cancellationToken);
        if (!metadata.HasValue)
        {
            return Result<Optional<FidoAttestationCertificateInspectionResult>>.Success(
                Optional<FidoAttestationCertificateInspectionResult>.Empty());
        }

        if (!TryGetAcceptableTrustAnchors(
                metadata.Value,
                acceptableAttestationTypes,
                out var acceptableTrustAnchors,
                out var attestationType))
        {
            return Result<Optional<FidoAttestationCertificateInspectionResult>>.Fail();
        }

        return Result<Optional<FidoAttestationCertificateInspectionResult>>.Success(
            Optional<FidoAttestationCertificateInspectionResult>.Payload(new(
                attestationType.Value,
                acceptableTrustAnchors)));
    }

    protected virtual async Task<Result<Optional<FidoAttestationCertificateInspectionResult>>> InspectUsingAaguidAsync(
        TContext context,
        Guid aaguid,
        IReadOnlySet<AttestationType> acceptableAttestationTypes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadata = await FidoMetadataService.FindMetadataByAaguidAsync(
            context,
            aaguid,
            cancellationToken);
        if (!metadata.HasValue)
        {
            return Result<Optional<FidoAttestationCertificateInspectionResult>>.Success(
                Optional<FidoAttestationCertificateInspectionResult>.Empty());
        }

        if (!TryGetAcceptableTrustAnchors(
                metadata.Value,
                acceptableAttestationTypes,
                out var acceptableTrustAnchors,
                out var attestationType))
        {
            return Result<Optional<FidoAttestationCertificateInspectionResult>>.Fail();
        }

        return Result<Optional<FidoAttestationCertificateInspectionResult>>.Success(
            Optional<FidoAttestationCertificateInspectionResult>.Payload(new(
                attestationType.Value,
                acceptableTrustAnchors)));
    }

    protected virtual bool TryGetAcceptableTrustAnchors(
        FidoMetadataResult metadata,
        IReadOnlySet<AttestationType> acceptableAttestationTypes,
        [NotNullWhen(true)] out AcceptableTrustAnchors? acceptableTrustAnchors,
        [NotNullWhen(true)] out AttestationType? attestationType)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (metadata is null)
        {
            acceptableTrustAnchors = null;
            attestationType = null;
            return false;
        }

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (acceptableAttestationTypes is null)
        {
            acceptableTrustAnchors = null;
            attestationType = null;
            return false;
        }


        if (acceptableAttestationTypes.Contains(AttestationType.AttCa)
            && metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_ATTCA))
        {
            acceptableTrustAnchors = new(metadata.RootCertificates, null);
            attestationType = AttestationType.AttCa;
            return true;
        }

        if (acceptableAttestationTypes.Contains(AttestationType.AnonCa)
            && metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_ANONCA))
        {
            acceptableTrustAnchors = new(metadata.RootCertificates, null);
            attestationType = AttestationType.AnonCa;
            return true;
        }

        if (acceptableAttestationTypes.Contains(AttestationType.Basic)
            && metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            acceptableTrustAnchors = new(metadata.RootCertificates, null);
            attestationType = AttestationType.Basic;
            return true;
        }

        if (acceptableAttestationTypes.Contains(AttestationType.Self)
            && metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_SURROGATE))
        {
            acceptableTrustAnchors = new(metadata.RootCertificates, null);
            attestationType = AttestationType.Self;
            return true;
        }

        if (acceptableAttestationTypes.Contains(AttestationType.None)
            && metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_NONE))
        {
            acceptableTrustAnchors = new(metadata.RootCertificates, null);
            attestationType = AttestationType.None;
            return true;
        }

        acceptableTrustAnchors = null;
        attestationType = null;
        return false;
    }

    protected virtual Result<Optional<byte[]>> TryGetSubjectKeyIdentifier(X509Certificate2 attestationCertificate)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attestationCertificate is null)
        {
            return Result<Optional<byte[]>>.Fail();
        }

        var subjectKeyIdentifierExtension = attestationCertificate.Extensions.FirstOrDefault(x => x is X509SubjectKeyIdentifierExtension);
        if (subjectKeyIdentifierExtension is X509SubjectKeyIdentifierExtension skiExtension)
        {
            var id = skiExtension.SubjectKeyIdentifier;
            if (!string.IsNullOrEmpty(id))
            {
                var binarySki = Convert.FromHexString(id);
                return Result<Optional<byte[]>>.Success(Optional<byte[]>.Payload(binarySki));
            }
        }

        return Result<Optional<byte[]>>.Success(Optional<byte[]>.Empty());
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual Result<Optional<Guid>> TryGetAaguid(X509Certificate2 attestationCertificate)
    {
        if (attestationCertificate is null)
        {
            return Result<Optional<Guid>>.Fail();
        }

        // If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
        // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
        // Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
        var extension = attestationCertificate.Extensions.FirstOrDefault(static x => x.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
        if (extension is not null)
        {
            if (extension.Critical)
            {
                return Result<Optional<Guid>>.Fail();
            }

            var decodeResult = Asn1Decoder.Decode(extension.RawData, AsnEncodingRules.BER);
            if (decodeResult.HasError)
            {
                return Result<Optional<Guid>>.Fail();
            }

            if (!decodeResult.Ok.HasValue)
            {
                return Result<Optional<Guid>>.Fail();
            }

            if (decodeResult.Ok.Value is not Asn1OctetString aaguidOctetString)
            {
                return Result<Optional<Guid>>.Fail();
            }

            if (aaguidOctetString.Value.Length != 16)
            {
                return Result<Optional<Guid>>.Fail();
            }

            var hexAaguid = Convert.ToHexString(aaguidOctetString.Value);
            var typedAaguid = new Guid(hexAaguid);
            return Result<Optional<Guid>>.Success(Optional<Guid>.Payload(typedAaguid));
        }

        return Result<Optional<Guid>>.Success(Optional<Guid>.Empty());
    }
}
