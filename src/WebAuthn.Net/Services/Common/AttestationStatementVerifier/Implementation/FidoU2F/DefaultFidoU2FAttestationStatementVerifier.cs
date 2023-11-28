using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.FidoU2F;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultFidoU2FAttestationStatementVerifier<TContext>
    : IFidoU2FAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    public DefaultFidoU2FAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IAsn1Deserializer asn1Deserializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(asn1Deserializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        TimeProvider = timeProvider;
        Asn1Deserializer = asn1Deserializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
    }

    protected ITimeProvider TimeProvider { get; }
    protected IAsn1Deserializer Asn1Deserializer { get; }
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        FidoU2FAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation
        // §8.6. FIDO U2F Attestation Statement Format

        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();

        // 1) Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Check that 'x5c' has exactly one element and let 'attCert' be that element.
        // Let certificate public key be the public key conveyed by 'attCert'.
        // If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.

        if (attStmt.X5C.Length != 1)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        X509Certificate2? attCert = null;
        try
        {
            var rawAttCert = attStmt.X5C[0];

            if (!X509CertificateInMemoryLoader.TryLoad(rawAttCert, out attCert))
            {
                attCert?.Dispose();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            if (currentDate < attCert.NotBefore || currentDate > attCert.NotAfter)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!IsValidPublicKeyParameters(attCert, out var attCertEcParameters))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 3) Extract the claimed 'rpIdHash' from 'authenticatorData', and the claimed 'credentialId' and 'credentialPublicKey'
            // from 'authenticatorData.attestedCredentialData'.
            var rpIdHash = authenticatorData.RpIdHash;
            var credentialId = authenticatorData.AttestedCredentialData.CredentialId;
            if (authenticatorData.AttestedCredentialData.CredentialPublicKey is not CoseEc2Key credentialPublicKey)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4) Convert the COSE_KEY formatted 'credentialPublicKey' (see Section 7 of [RFC9052])
            // to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
            if (!TryConvertCoseKeyToPublicKeyU2F(credentialPublicKey, out var publicKeyU2F))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5) Let 'verificationData' be the concatenation of
            // (0x00 || 'rpIdHash' || 'clientDataHash' || 'credentialId' || 'publicKeyU2F') (see Section 4.3 of [FIDO-U2F-Message-Formats]).
            var verificationData = Concat(stackalloc byte[1] { 0x00 }, rpIdHash, clientDataHash, credentialId, publicKeyU2F);

            // 6) Verify the 'sig' using 'verificationData' and the certificate public key per section 4.1.4 of [SEC1]
            // with SHA-256 as the hash function used in step two.
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new()
                {
                    X = attCertEcParameters.Value.Q.X,
                    Y = attCertEcParameters.Value.Q.Y
                }
            });
            if (!ecdsa.VerifyData(verificationData, attStmt.Sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 7) Optionally, inspect 'x5c' and consult externally provided knowledge to determine whether 'attStmt' conveys a Basic or AttCA attestation.
            var attestationTypeResult = await GetAttestationTypeAsync(
                context,
                attCert,
                authenticatorData,
                cancellationToken);
            if (attestationTypeResult.HasError)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 8) If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.
            var result = new VerifiedAttestationStatement(
                AttestationStatementFormat.FidoU2F,
                attestationTypeResult.Ok.AttestationType,
                new[] { rawAttCert },
                new(attestationTypeResult.Ok.AttestationRootCertificates));
            return Result<VerifiedAttestationStatement>.Success(result);
        }
        finally
        {
            attCert?.Dispose();
        }
    }

    protected virtual async Task<Result<FidoU2FAttestationTypeResult>> GetAttestationTypeAsync(
        TContext context,
        X509Certificate2 attCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();
        var metadataResult = await TryGetFidoMetadataAsync(context, attCert, authenticatorData, cancellationToken);
        if (metadataResult.HasError)
        {
            return Result<FidoU2FAttestationTypeResult>.Fail();
        }

        var metadata = metadataResult.Ok;
        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_ATTCA))
        {
            var rootCertificates = new UniqueByteArraysCollection();
            rootCertificates.AddRange(metadata.RootCertificates);
            return Result<FidoU2FAttestationTypeResult>.Success(new(AttestationType.AttCa, rootCertificates));
        }

        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            var rootCertificates = new UniqueByteArraysCollection();
            rootCertificates.AddRange(metadata.RootCertificates);
            return Result<FidoU2FAttestationTypeResult>.Success(new(AttestationType.Basic, rootCertificates));
        }

        return Result<FidoU2FAttestationTypeResult>.Fail();
    }

    protected virtual async Task<Result<FidoMetadataResult>> TryGetFidoMetadataAsync(
        TContext context,
        X509Certificate2 attCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (authenticatorData is null)
        {
            return Result<FidoMetadataResult>.Fail();
        }

        if (authenticatorData.AttestedCredentialData.Aaguid != Guid.Empty)
        {
            var aaguidResult = await FidoMetadataSearchService.FindMetadataByAaguidAsync(
                context,
                authenticatorData.AttestedCredentialData.Aaguid,
                cancellationToken);
            if (aaguidResult.HasValue)
            {
                return Result<FidoMetadataResult>.Success(aaguidResult.Value);
            }
        }
        else
        {
            var embeddedAaguidResult = GetAaguidIfExists(attCert);
            if (embeddedAaguidResult.HasError)
            {
                return Result<FidoMetadataResult>.Fail();
            }

            var embeddedAaguidOptional = embeddedAaguidResult.Ok;
            if (embeddedAaguidOptional.HasValue)
            {
                var embeddedAaguidMetadataResult = await FidoMetadataSearchService.FindMetadataByAaguidAsync(
                    context,
                    embeddedAaguidOptional.Value,
                    cancellationToken);
                if (embeddedAaguidMetadataResult.HasValue)
                {
                    return Result<FidoMetadataResult>.Success(embeddedAaguidMetadataResult.Value);
                }

                return Result<FidoMetadataResult>.Fail();
            }

            var embeddedSkiResult = GetSubjectKeyIdentifierIfExists(attCert);
            if (embeddedSkiResult.HasError)
            {
                return Result<FidoMetadataResult>.Fail();
            }

            var embeddedSkiOptional = embeddedSkiResult.Ok;
            if (embeddedSkiOptional.HasValue)
            {
                var embeddedSkiMetadataResult = await FidoMetadataSearchService.FindMetadataBySubjectKeyIdentifierAsync(
                    context,
                    embeddedSkiOptional.Value,
                    cancellationToken);
                if (embeddedSkiMetadataResult.HasValue)
                {
                    return Result<FidoMetadataResult>.Success(embeddedSkiMetadataResult.Value);
                }

                return Result<FidoMetadataResult>.Fail();
            }
        }


        // var ski = TryGetSubjectKeyIdentifier(attCert);
        // if (!ski.HasValue)
        // {
        //     return Result<FidoMetadataResult>.Fail();
        // }
        //
        // var skiResult = await FidoMetadataSearchService.FindMetadataBySubjectKeyIdentifierAsync(
        //     context,
        //     ski.Value,
        //     cancellationToken);
        // if (skiResult.HasValue)
        // {
        //     return Result<FidoMetadataResult>.Success(skiResult.Value);
        // }


        return Result<FidoMetadataResult>.Fail();
    }

    protected virtual Result<Optional<byte[]>> GetSubjectKeyIdentifierIfExists(X509Certificate2 attCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attCert is null)
        {
            return Result<Optional<byte[]>>.Fail();
        }

        var subjectKeyIdentifierExtension = attCert.Extensions.FirstOrDefault(x => x is X509SubjectKeyIdentifierExtension);
        if (subjectKeyIdentifierExtension is X509SubjectKeyIdentifierExtension skiExtension)
        {
            var hexSki = skiExtension.SubjectKeyIdentifier;
            if (!string.IsNullOrEmpty(hexSki))
            {
                var binarySki = Convert.FromHexString(hexSki);
                return Result<Optional<byte[]>>.Success(Optional<byte[]>.Payload(binarySki));
            }
        }

        return Result<Optional<byte[]>>.Success(Optional<byte[]>.Empty());
    }

    protected virtual Result<Optional<Guid>> GetAaguidIfExists(X509Certificate2 attCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attCert is null)
        {
            return Result<Optional<Guid>>.Fail();
        }

        // If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
        // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
        // Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
        var extension = attCert.Extensions.FirstOrDefault(static x => x.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
        if (extension is not null)
        {
            if (extension.Critical)
            {
                return Result<Optional<Guid>>.Fail();
            }

            var deserializeResult = Asn1Deserializer.Deserialize(extension.RawData, AsnEncodingRules.BER);
            if (deserializeResult.HasError)
            {
                return Result<Optional<Guid>>.Fail();
            }

            if (!deserializeResult.Ok.HasValue)
            {
                return Result<Optional<Guid>>.Fail();
            }

            if (deserializeResult.Ok.Value is not Asn1OctetString aaguidOctetString)
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

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool IsValidPublicKeyParameters(X509Certificate2 attCert, [NotNullWhen(true)] out ECParameters? attCertEcParameters)
    {
        //  If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
        if (attCert is null)
        {
            attCertEcParameters = null;
            return false;
        }

        var ecDsaPubKey = attCert.GetECDsaPublicKey();
        if (ecDsaPubKey is null)
        {
            attCertEcParameters = null;
            return false;
        }

        var parameters = ecDsaPubKey.ExportParameters(false);
        if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            attCertEcParameters = null;
            return false;
        }

        attCertEcParameters = parameters;
        return true;
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryConvertCoseKeyToPublicKeyU2F(CoseEc2Key credentialPublicKey, [NotNullWhen(true)] out byte[]? publicKeyU2F)
    {
        if (credentialPublicKey is null)
        {
            publicKeyU2F = null;
            return false;
        }

        // Let 'x' be the value corresponding to the "-2" key (representing x coordinate) in 'credentialPublicKey',
        // and confirm its size to be of 32 bytes.
        // If size differs or "-2" key is not found, terminate this algorithm and return an appropriate error.
        if (credentialPublicKey.X.Length != 32)
        {
            publicKeyU2F = null;
            return false;
        }

        // Let 'y' be the value corresponding to the "-3" key (representing y coordinate) in 'credentialPublicKey',
        // and confirm its size to be of 32 bytes.
        // If size differs or "-3" key is not found, terminate this algorithm and return an appropriate error.
        if (credentialPublicKey.Y.Length != 32)
        {
            publicKeyU2F = null;
            return false;
        }

        // Let 'publicKeyU2F' be the concatenation 0x04 || 'x' || 'y'.
        publicKeyU2F = Concat(stackalloc byte[1] { 0x04 }, credentialPublicKey.X, credentialPublicKey.Y);
        return true;
    }

    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        var result = new byte[a.Length + b.Length + c.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        return result;
    }

    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        var result = new byte[a.Length + b.Length + c.Length + d.Length + e.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        d.CopyTo(result.AsSpan(a.Length + b.Length + c.Length));
        e.CopyTo(result.AsSpan(a.Length + b.Length + c.Length + d.Length));
        return result;
    }
}
