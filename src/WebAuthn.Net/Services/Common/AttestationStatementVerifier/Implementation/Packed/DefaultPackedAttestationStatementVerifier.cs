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
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Packed;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Packed;

public class DefaultPackedAttestationStatementVerifier<TContext> :
    IPackedAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    private readonly IReadOnlySet<AttestationType> _supportedAttestationTypes = new HashSet<AttestationType>
    {
        AttestationType.Basic,
        AttestationType.AttCa,
        AttestationType.Self
    };

    public DefaultPackedAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier,
        IAsn1Decoder asn1Decoder,
        IFidoAttestationCertificateInspector<TContext> fidoAttestationCertificateInspector)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(asn1Decoder);
        ArgumentNullException.ThrowIfNull(fidoAttestationCertificateInspector);
        TimeProvider = timeProvider;
        SignatureVerifier = signatureVerifier;
        Asn1Decoder = asn1Decoder;
        FidoAttestationCertificateInspector = fidoAttestationCertificateInspector;
    }

    protected ITimeProvider TimeProvider { get; }
    protected IDigitalSignatureVerifier SignatureVerifier { get; }
    protected IAsn1Decoder Asn1Decoder { get; }
    protected IFidoAttestationCertificateInspector<TContext> FidoAttestationCertificateInspector { get; }

    public virtual async Task<Result<AttestationStatementVerificationResult>> VerifyAsync(
        TContext context,
        PackedAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-packed-attestation
        // §8.2. Packed Attestation Statement Format

        ArgumentNullException.ThrowIfNull(attStmt);
        cancellationToken.ThrowIfCancellationRequested();
        // 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) If x5c is present:
        if (attStmt.X5C is not null)
        {
            var certificatesToDispose = new List<X509Certificate2>();
            try
            {
                var currentDate = TimeProvider.GetPreciseUtcDateTime();
                var x5CCertificates = new List<X509Certificate2>(attStmt.X5C.Length);
                foreach (var x5CBytes in attStmt.X5C)
                {
                    if (!X509CertificateInMemoryLoader.TryLoad(x5CBytes, out var x5CCert))
                    {
                        x5CCert?.Dispose();
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    certificatesToDispose.Add(x5CCert);
                    x5CCertificates.Add(x5CCert);
                    if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                    {
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    if (IsRootCertificate(x5CCert))
                    {
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }
                }

                var x5CResult = await VerifyPackedWithX5CAsync(
                    context,
                    attStmt,
                    authenticatorData,
                    clientDataHash,
                    x5CCertificates,
                    attStmt.X5C,
                    cancellationToken);
                return x5CResult;
            }
            finally
            {
                foreach (var certificateToDispose in certificatesToDispose)
                {
                    certificateToDispose.Dispose();
                }
            }
        }

        // 3) If x5c is not present, self attestation is in use.
        var noX5CResult = VerifyPackedWithoutX5C(attStmt, authenticatorData, clientDataHash);
        return noX5CResult;
    }

    protected virtual bool IsRootCertificate(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        return cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData.AsSpan());
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual async Task<Result<AttestationStatementVerificationResult>> VerifyPackedWithX5CAsync(
        TContext context,
        PackedAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        IReadOnlyCollection<X509Certificate2> certificates,
        byte[][] trustPath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (attStmt is null || authenticatorData is null)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // If x5c is present
        // 1) Verify that 'sig' is a valid signature over the concatenation of 'authenticatorData' and 'clientDataHash'
        // using the attestation public key in 'attestnCert' with the algorithm specified in 'alg'.

        // The attestation certificate 'attestnCert' MUST be the first element in the array.
        var attestnCert = certificates.First();
        var dataToVerify = Concat(authenticatorData.Raw, clientDataHash);
        if (!SignatureVerifier.IsValidCertificateSign(attestnCert, attStmt.Alg, dataToVerify, attStmt.Sig))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 2) Verify that 'attestnCert' meets the requirements in §8.2.1 Packed Attestation Statement Certificate Requirements.
        if (!IsAttestnCertValid(attestnCert, out var aaguid))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3) If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
        // verify that the value of this extension matches the 'aaguid' in 'authenticatorData'.
        if (aaguid.HasValue && authenticatorData.AttestedCredentialData.Aaguid != aaguid.Value)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 4) Optionally, inspect 'x5c' and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.
        var inspectResult = await FidoAttestationCertificateInspector.InspectAttestationCertificateAsync(
            context,
            attestnCert,
            authenticatorData,
            GetSupportedAttestationTypes(),
            cancellationToken);
        if (inspectResult.HasError || !inspectResult.Ok.HasValue)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        var inspectionResult = inspectResult.Ok.Value;

        // 5) If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path 'x5c'.
        var result = new AttestationStatementVerificationResult(
            AttestationStatementFormat.Packed,
            inspectionResult.AttestationType,
            trustPath,
            inspectionResult.AcceptableTrustAnchors);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    protected virtual IReadOnlySet<AttestationType> GetSupportedAttestationTypes()
    {
        return _supportedAttestationTypes;
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual Result<AttestationStatementVerificationResult> VerifyPackedWithoutX5C(
        PackedAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash)
    {
        if (attStmt is null || authenticatorData is null)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // If x5c is not present, self attestation is in use.
        // 1) Validate that 'alg' matches the algorithm of the 'credentialPublicKey' in 'authenticatorData'.
        if (attStmt.Alg != authenticatorData.AttestedCredentialData.CredentialPublicKey.Alg)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 2) Verify that 'sig' is a valid signature over the concatenation of 'authenticatorData' and 'clientDataHash'
        // using the credential public key with 'alg'.
        var dataToVerify = Concat(authenticatorData.Raw, clientDataHash);
        if (!SignatureVerifier.IsValidCoseKeySign(authenticatorData.AttestedCredentialData.CredentialPublicKey, dataToVerify, attStmt.Sig))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3) If successful, return implementation-specific values representing attestation type Self and an empty attestation trust path.
        var result = new AttestationStatementVerificationResult(
            AttestationStatementFormat.Packed,
            AttestationType.Self,
            null,
            null);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool IsAttestnCertValid(X509Certificate2 attestnCert, [NotNullWhen(true)] out Optional<Guid>? aaguid)
    {
        // §8.2.1 Packed Attestation Statement Certificate Requirements.
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-packed-attestation-cert-requirements

        if (attestnCert is null)
        {
            aaguid = null;
            return false;
        }

        // 1 - Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
        if (attestnCert.Version != 3)
        {
            aaguid = null;
            return false;
        }

        // Subject field MUST be set to:
        // Subject-C - ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        // Subject-O - Legal name of the Authenticator vendor (UTF8String)
        // Subject-OU - Literal string "Authenticator Attestation" (UTF8String)
        // Subject-CN - A UTF8String of the vendor's choosing
        if (!IsValidSubject(attestnCert.SubjectName))
        {
            aaguid = null;
            return false;
        }

        // 3 - If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING.
        // The extension MUST NOT be marked as critical.
        var extensions = attestnCert.Extensions;
        var aaguidResult = TryGetAaguid(extensions);
        if (aaguidResult.HasError)
        {
            aaguid = null;
            return false;
        }

        // 4 - The Basic Constraints extension MUST have the CA component set to false.
        if (!IsBasicExtensionsCaComponentFalse(extensions))
        {
            aaguid = null;
            return false;
        }

        // 5 - An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280]
        // are both OPTIONAL as the status of many attestation certificates is available through authenticator metadata services.
        // See, for example, the FIDO Metadata Service [FIDOMetadataService].
        aaguid = aaguidResult.Ok;
        return true;
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool IsValidSubject(X500DistinguishedName subjectName)
    {
        if (subjectName is null)
        {
            return false;
        }
        // Subject field MUST be set to:
        // Subject-C - ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        // Subject-O - Legal name of the Authenticator vendor (UTF8String)
        // Subject-OU - Literal string "Authenticator Attestation" (UTF8String)
        // Subject-CN - A UTF8String of the vendor's choosing

        // form the string for splitting using new lines to avoid issues with commas
        var subjectString = subjectName.Decode(X500DistinguishedNameFlags.UseNewLines);
        var subjectMap = new Dictionary<string, string>(4);

        foreach (var line in subjectString.AsSpan().EnumerateLines())
        {
            var equalIndex = line.IndexOf('=');
            if (equalIndex < 0)
            {
                return false;
            }

            var leftHandSide = line[..equalIndex].ToString();
            var rightHandSide = line[(equalIndex + 1)..].ToString();
            subjectMap[leftHandSide] = rightHandSide;
        }

        // ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        if (!subjectMap.TryGetValue("C", out var subjectC))
        {
            return false;
        }

        if (string.IsNullOrEmpty(subjectC))
        {
            return false;
        }

        // Legal name of the Authenticator vendor (UTF8String)
        if (!subjectMap.TryGetValue("O", out var subjectO))
        {
            return false;
        }

        if (string.IsNullOrEmpty(subjectO))
        {
            return false;
        }

        // Literal string "Authenticator Attestation" (UTF8String)
        if (!subjectMap.TryGetValue("OU", out var subjectOu))
        {
            return false;
        }

        if (!string.Equals(subjectOu, "Authenticator Attestation", StringComparison.Ordinal))
        {
            return false;
        }

        // A UTF8String of the vendor's choosing
        if (!subjectMap.TryGetValue("CN", out var subjectCn))
        {
            return false;
        }

        if (string.IsNullOrEmpty(subjectCn))
        {
            return false;
        }

        return true;
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual Result<Optional<Guid>> TryGetAaguid(X509ExtensionCollection extensions)
    {
        if (extensions is null)
        {
            return Result<Optional<Guid>>.Fail();
        }

        // If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
        // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
        // Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
        var extension = extensions.FirstOrDefault(static x => x.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
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

    protected virtual bool IsBasicExtensionsCaComponentFalse(X509ExtensionCollection extensions)
    {
        // The Basic Constraints extension MUST have the CA component set to false.
        var extension = extensions.FirstOrDefault(static e => e.Oid?.Value is "2.5.29.19");
        if (extension is X509BasicConstraintsExtension basicExtension)
        {
            var isCaCert = basicExtension.CertificateAuthority;
            var isCaComponentFalse = isCaCert == false;
            return isCaComponentFalse;
        }

        return false;
    }

    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
