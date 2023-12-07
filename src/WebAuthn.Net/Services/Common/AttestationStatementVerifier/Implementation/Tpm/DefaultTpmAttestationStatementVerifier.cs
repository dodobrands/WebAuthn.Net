using System;
using System.Buffers.Binary;
using System.Collections.Generic;
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
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

/// <summary>
///     Default implementation of <see cref="ITpmAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultTpmAttestationStatementVerifier<TContext> : ITpmAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultTpmAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="tpmPubAreaDecoder">
    ///     Decoder of the TPMT_PUBLIC structure, defined in the <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (section 12.2.4)</a>, from binary into a typed representation.
    /// </param>
    /// <param name="tpmCertInfoDecoder">
    ///     Decoder of the TPMS_ATTEST structure over which the above signature was computed, as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (section 10.12.12)</a>.
    /// </param>
    /// <param name="signatureVerifier">Digital signature verifier.</param>
    /// <param name="tpmManufacturerVerifier">Verifier of TPM module manufacturer.</param>
    /// <param name="asn1Deserializer">ASN.1 format deserializer.</param>
    /// <param name="fidoMetadataSearchService">A service for searching in the data provided by the FIDO Metadata Service.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultTpmAttestationStatementVerifier(
        ITimeProvider timeProvider,
        ITpmPubAreaDecoder tpmPubAreaDecoder,
        ITpmCertInfoDecoder tpmCertInfoDecoder,
        IDigitalSignatureVerifier signatureVerifier,
        ITpmManufacturerVerifier tpmManufacturerVerifier,
        IAsn1Deserializer asn1Deserializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(tpmPubAreaDecoder);
        ArgumentNullException.ThrowIfNull(tpmCertInfoDecoder);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(tpmManufacturerVerifier);
        ArgumentNullException.ThrowIfNull(asn1Deserializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        TimeProvider = timeProvider;
        TpmPubAreaDecoder = tpmPubAreaDecoder;
        TpmCertInfoDecoder = tpmCertInfoDecoder;
        SignatureVerifier = signatureVerifier;
        TpmManufacturerVerifier = tpmManufacturerVerifier;
        Asn1Deserializer = asn1Deserializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
    }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Decoder of the TPMT_PUBLIC structure, defined in the <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (section 12.2.4)</a>, from binary into a typed representation.
    /// </summary>
    protected ITpmPubAreaDecoder TpmPubAreaDecoder { get; }

    /// <summary>
    ///     Decoder of the TPMS_ATTEST structure over which the above signature was computed, as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (section 10.12.12)</a>.
    /// </summary>
    protected ITpmCertInfoDecoder TpmCertInfoDecoder { get; }

    /// <summary>
    ///     Digital signature verifier.
    /// </summary>
    protected IDigitalSignatureVerifier SignatureVerifier { get; }

    /// <summary>
    ///     Verifier of TPM module manufacturer.
    /// </summary>
    protected ITpmManufacturerVerifier TpmManufacturerVerifier { get; }

    /// <summary>
    ///     ASN.1 format deserializer.
    /// </summary>
    protected IAsn1Deserializer Asn1Deserializer { get; }

    /// <summary>
    ///     A service for searching in the data provided by the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    /// <inheritdoc />
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        TpmAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-attestation
        // §8.3. TPM Attestation Statement Format

        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        // 1 - Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2 - Verify that the public key specified by the 'parameters' and 'unique' fields of 'pubArea'
        // is identical to the 'credentialPublicKey' in the 'attestedCredentialData' in 'authenticatorData'.
        var pubAreaResult = TpmPubAreaDecoder.Decode(attStmt.PubArea);
        if (pubAreaResult.HasError)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        if (!PubAreaKeySameAsAttestedCredentialData(pubAreaResult.Ok, authenticatorData.AttestedCredentialData.CredentialPublicKey))
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 3 - Concatenate 'authenticatorData' and 'clientDataHash' to form 'attToBeSigned'.
        var attToBeSigned = Concat(authenticatorData.Raw, clientDataHash);

        // 4 - Validate that 'certInfo' is valid:
        return await ValidateCertInfoAsync(context, attStmt, authenticatorData, attToBeSigned, cancellationToken);
    }

    /// <summary>
    ///     Verifies that the public key specified by the 'parameters' and 'unique' fields of 'pubArea' is identical to the 'credentialPublicKey' in the 'attestedCredentialData' in 'authenticatorData'.
    /// </summary>
    /// <param name="pubArea">Decoded 'pubArea' (structure used by the TPM to represent the credential public key).</param>
    /// <param name="authDataKey"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">Credential public key</a> from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> in COSE format.</param>
    /// <returns><see langword="true" /> if the keys are identical, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool PubAreaKeySameAsAttestedCredentialData(PubArea pubArea, AbstractCoseKey authDataKey)
    {
        if (pubArea is null || authDataKey is null)
        {
            return false;
        }

        bool matches;
        if (!TryToAsymmetricAlgorithm(pubArea, out var algorithm))
        {
            return false;
        }

        using (algorithm)
        {
            matches = authDataKey.Matches(algorithm);
        }

        return matches;
    }

    /// <summary>
    ///     Validates that the certInfo is valid.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attStmt">Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-attestation">TPM attestation statement</a>.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="attToBeSigned">The result of concatenating 'authenticatorData' and 'clientDataHash' to form 'attToBeSigned'.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the verification is successful - the result containing <see cref="VerifiedAttestationStatement" />, otherwise - the result indicating that the validation has failed.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual async Task<Result<VerifiedAttestationStatement>> ValidateCertInfoAsync(
        TContext context,
        TpmAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] attToBeSigned,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (attStmt is null || authenticatorData is null)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-attestation
        // §8.3. TPM Attestation Statement Format
        // Validate that certInfo is valid:
        // 1) Verify that 'magic' is set to TPM_GENERATED_VALUE.
        // Handled in CertInfo.TryParse
        // 2) Verify that 'type' is set to TPM_ST_ATTEST_CERTIFY.
        // Handled in CertInfo.TryParse
        var certInfoResult = TpmCertInfoDecoder.Decode(attStmt.CertInfo);
        if (certInfoResult.HasError)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        var certInfo = certInfoResult.Ok;

        // 3) Verify that 'extraData' is set to the hash of 'attToBeSigned' using the hash algorithm employed in 'alg'.
        if (!attStmt.Alg.TryComputeHash(attToBeSigned, out var attToBeSignedHash))
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        if (!certInfo.ExtraData.AsSpan().SequenceEqual(attToBeSignedHash.AsSpan()))
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 4) Verify that 'attested' contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3,
        // whose 'name' field contains a valid Name for 'pubArea', as computed using the algorithm in the 'nameAlg' field of 'pubArea'
        // using the procedure specified in [TPMv2-Part1] section 16.
        if (certInfo.Attested.Certify.Name.Digest is null)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        if (!TryComputeHash(certInfo.Attested.Certify.Name.Digest.HashAlg, attStmt.PubArea, out var pubAreaHash))
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        if (!pubAreaHash.AsSpan().SequenceEqual(certInfo.Attested.Certify.Name.Digest.Digest.AsSpan()))
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 5) Verify that x5c is present.
        if (attStmt.X5C.Length == 0)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        var certificatesToDispose = new List<X509Certificate2>(attStmt.X5C.Length);
        try
        {
            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var x5CCertificates = new List<X509Certificate2>(attStmt.X5C.Length);
            foreach (var x5CBytes in attStmt.X5C)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(x5CBytes, out var x5CCert))
                {
                    x5CCert?.Dispose();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                certificatesToDispose.Add(x5CCert);
                x5CCertificates.Add(x5CCert);
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    return Result<VerifiedAttestationStatement>.Fail();
                }
            }

            var aikCert = x5CCertificates.First();

            // 5) Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2,
            // i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.

            // 6) Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2, i.e.,
            // 'qualifiedSigner', 'clockInfo' and 'firmwareVersion' are ignored.
            // These fields MAY be used as an input to risk engines.

            // 7) Verify the 'sig' is a valid signature over 'certInfo' using the attestation public key in 'aikCert' with the algorithm specified in 'alg'.
            if (!SignatureVerifier.IsValidCertificateSign(aikCert, attStmt.Alg, attStmt.CertInfo, attStmt.Sig))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 8) Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.
            if (!IsTpmAttestationStatementCertificateRequirementsSatisfied(aikCert, out var manufacturerRootCertificates))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 9) If 'aikCert' contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
            // verify that the value of this extension matches the 'aaguid' in 'authenticatorData'.
            var aaguidResult = GetAaguidIfExists(aikCert);
            if (aaguidResult.HasError)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (aaguidResult.Ok.HasValue && aaguidResult.Ok.Value != authenticatorData.AttestedCredentialData.Aaguid)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 10) If successful, return implementation-specific values representing attestation type AttCA and attestation trust path 'x5c'.
            var acceptableTrustAnchorsResult = await GetAcceptableTrustAnchorsAsync(
                context,
                aikCert,
                manufacturerRootCertificates,
                authenticatorData,
                cancellationToken);
            if (acceptableTrustAnchorsResult.HasError)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var result = new VerifiedAttestationStatement(
                AttestationStatementFormat.Tpm,
                AttestationType.AttCa,
                attStmt.X5C,
                acceptableTrustAnchorsResult.Ok);
            return Result<VerifiedAttestationStatement>.Success(result);
        }
        finally
        {
            foreach (var certificateToDispose in certificatesToDispose)
            {
                certificateToDispose.Dispose();
            }
        }
    }

    /// <summary>
    ///     Returns a collection of valid root X509v3 certificates.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="aikCert">The AIK certificate used for the attestation, in X.509 encoding.</param>
    /// <param name="manufacturerRootCertificates">Root CA x509v3 certificates of the specific TPM module manufacturer. May be null.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the collection of root certificates was successfully formed, the result contains <see cref="UniqueByteArraysCollection" />, otherwise the result indicates that there was an error during the collection formation process.</returns>
    protected virtual async Task<Result<UniqueByteArraysCollection>> GetAcceptableTrustAnchorsAsync(
        TContext context,
        X509Certificate2 aikCert,
        UniqueByteArraysCollection? manufacturerRootCertificates,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();

        var rootCertificates = new UniqueByteArraysCollection();
        if (manufacturerRootCertificates is not null && manufacturerRootCertificates.Count > 0)
        {
            rootCertificates.AddRange(manufacturerRootCertificates);
        }

        var metadataRoots = await GetAcceptableTrustAnchorsFromFidoMetadataAsync(
            context,
            authenticatorData.AttestedCredentialData.Aaguid,
            cancellationToken);

        if (metadataRoots is not null)
        {
            rootCertificates.AddRange(metadataRoots);
        }

        return Result<UniqueByteArraysCollection>.Success(new(rootCertificates));
    }

    /// <summary>
    ///     Returns a collection of valid root certificates from the Fido Metadata Service.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the Fido Metadata Service contains root certificates for the specified <paramref name="aaguid" /> - then <see cref="UniqueByteArraysCollection" />, otherwise - <see langword="null" />.</returns>
    protected virtual async Task<UniqueByteArraysCollection?> GetAcceptableTrustAnchorsFromFidoMetadataAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadata = await FidoMetadataSearchService.FindMetadataByAaguidAsync(context, aaguid, cancellationToken);
        if (metadata is null)
        {
            return null;
        }

        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_ATTCA))
        {
            var result = new UniqueByteArraysCollection();
            // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
            if (metadata.RootCertificates?.Length > 0)
            {
                result.AddRange(metadata.RootCertificates);
            }

            return result;
        }

        return null;
    }

    /// <summary>
    ///     Verifies that the AIK certificate used for the attestation satisfies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-cert-requirements">TPM attestation statement certificate requirements (section 8.3.1 of the WebAuthn specification)</a>, and also in
    ///     case of success may return a collection of Root CA X509v3 certificates of the TPM module manufacturer in the out parameter.
    /// </summary>
    /// <param name="aikCert">The AIK certificate used for the attestation, in X.509 encoding.</param>
    /// <param name="manufacturerRootCertificates">An output parameter that may contain a collection of Root CA X509v3 certificates of the TPM module manufacturer in case of successful verification. May be null.</param>
    /// <returns><see langword="true" /> if the AIK certificate was successfully verified, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool IsTpmAttestationStatementCertificateRequirementsSatisfied(
        X509Certificate2 aikCert,
        out UniqueByteArraysCollection? manufacturerRootCertificates)
    {
        if (aikCert is null)
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-cert-requirements
        // §8.3.1. TPM Attestation Statement Certificate Requirements
        // TPM attestation certificate MUST have the following fields/extensions:
        // 1) Version MUST be set to 3.
        if (aikCert.Version != 3)
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // 2) Subject field MUST be set to empty.
        if (aikCert.SubjectName.Name.Length > 0)
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // 3) The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
        // https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-V-2.5-R2_published.pdf
        if (!TryGetAikCertSubjectAlternativeName(aikCert, out var san))
        {
            manufacturerRootCertificates = null;
            return false;
        }

        var manufacturerVerification = TpmManufacturerVerifier.IsValid(san.TpmManufacturer);
        if (manufacturerVerification.HasError)
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // 4) The Extended Key Usage extension MUST contain the OID 2.23.133.8.3
        // ("joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)").
        if (!AikCertExtendedKeyUsageExists(aikCert.Extensions))
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // 5) The Basic Constraints extension MUST have the CA component set to false.
        if (!IsBasicExtensionsCaComponentFalse(aikCert.Extensions))
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // 6) An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280]
        // are both OPTIONAL as the status of many attestation certificates is available through metadata services.
        // See, for example, the FIDO Metadata Service [FIDOMetadataService].
        manufacturerRootCertificates = manufacturerVerification.Ok;
        return true;
    }

    /// <summary>
    ///     Extracts and decodes the subject alternative name (SAN) certificate extension from the AIK certificate used for attestation.
    /// </summary>
    /// <param name="aikCert">The AIK certificate used for the attestation, in X.509 encoding.</param>
    /// <param name="san">Output parameter. If the method returns <see langword="true" />, then it must not be <see langword="null" /> and should contain the decoded Subject Alternative Name (SAN) certificate extension.</param>
    /// <returns><see langword="true" /> if succeeded in extracting and decoding the subject alternative name (SAN) certificate extension from the AIK certificate used for attestation, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetAikCertSubjectAlternativeName(
        X509Certificate2 aikCert,
        [NotNullWhen(true)] out AikCertSubjectAlternativeName? san)
    {
        const string subjectAlternativeNameOid = "2.5.29.17";
        const string tpmManufacturer = "2.23.133.2.1";
        const string tpmModel = "2.23.133.2.2";
        const string tpmVersion = "2.23.133.2.3";
        if (aikCert is null)
        {
            san = null;
            return false;
        }

        var sanExtension = aikCert.Extensions.FirstOrDefault(x => x.Oid?.Value == subjectAlternativeNameOid);
        if (sanExtension is null)
        {
            san = null;
            return false;
        }

        if (!TryParseSanExtensionValues(sanExtension.RawData, out var values))
        {
            san = null;
            return false;
        }

        if (!values.TryGetValue(tpmManufacturer, out var manufacturer))
        {
            san = null;
            return false;
        }

        if (!values.TryGetValue(tpmModel, out var model))
        {
            san = null;
            return false;
        }

        if (!values.TryGetValue(tpmVersion, out var version))
        {
            san = null;
            return false;
        }

        san = new(manufacturer, model, version);
        return true;
    }

    /// <summary>
    ///     Decodes subject alternative name (SAN) certificate extension from ASN.1 format into a typed representation.
    /// </summary>
    /// <param name="extension">Subject alternative name (SAN) certificate extension in ASN.1 format.</param>
    /// <param name="values">Output parameter. If the method returns <see langword="true" /> - it must not be <see langword="null" /> and should contain decoded values as a dictionary.</param>
    /// <returns><see langword="true" /> if the subject alternative name was successfully decoded, otherwise - <see langword="false" />.</returns>
    protected virtual bool TryParseSanExtensionValues(byte[] extension, [NotNullWhen(true)] out Dictionary<string, string>? values)
    {
        // https://trustedcomputinggroup.org/resource/http-trustedcomputinggroup-org-wp-content-uploads-tcg-ek-credential-profile-v-2-5-r2_published-pdf/
        // 3 X.509 ASN.1 Definitions
        // This section contains the format for the EK Credential instantiated as an X.509 certificate. All fields are defined in ASN.1 and encoded using DER [19].
        // A. Certificate Examples
        // A.1 Example 1 (user device TPM, e.g. PC-Client)
        // Subject alternative name:
        // TPMManufacturer = id:54534700 (TCG)
        // TPMModel = ABCDEF123456 (part number)
        // TPMVersion = id:00010023 (firmware version)
        // // SEQUENCE
        // 30 49
        //      // SET
        //      31 16
        //          // SEQUENCE
        //          30 14
        //              // OBJECT IDENTIFER tcg-at-tpmManufacturer (2.23.133.2.1)
        //              06 05 67 81 05 02 01
        //              // UTF8 STRING id:54434700 (TCG)
        //              0C 0B 69 64 3A 35 34 34 33 34 37 30 30
        //     // SET
        //     31 17
        //         // SEQUENCE
        //         30 15
        //             // OBJECT IDENTIFER tcg-at-tpmModel (2.23.133.2.2)
        //             06 05 67 81 05 02 02
        //             // UTF8 STRING ABCDEF123456
        //             0C 0C 41 42 43 44 45 46 31 32 33 34 35 36
        //     // SET
        //     31 16
        //         // SEQUENCE
        //         30 14
        //             // OBJECT IDENTIFER tcg-at-tpmVersion (2.23.133.2.3)
        //             06 05 67 81 05 02 03
        //             // UTF8 STRING id:00010023
        //             0C 0B 69 64 3A 30 30 30 31 30 30 32 33
        // ---------------------------------------------
        // A real TPM module may return such a structure:
        // Certificate SEQUENCE (1 elem)
        //   tbsCertificate TBSCertificate [?] [4] (1 elem)
        //     serialNumber CertificateSerialNumber [?] SEQUENCE (3 elem)
        //       SET (1 elem)
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.1 tcgTpmManufacturer (TCPA/TCG Attribute)
        //           UTF8String id:414D4400
        //       SET (1 elem)
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.2 tcgTpmModel (TCPA/TCG Attribute)
        //           UTF8String AMD
        //       SET (1 elem)
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.3 tcgTpmVersion (TCPA/TCG Attribute)
        //           UTF8String id:00030001
        // ---------------------------------------------
        // sometimes something like this
        // Certificate SEQUENCE (1 elem)
        //   tbsCertificate TBSCertificate [?] [4] (1 elem)
        //     serialNumber CertificateSerialNumber [?] SEQUENCE (1 elem)
        //       SET (3 elem)
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.3 tcgTpmVersion (TCPA/TCG Attribute)
        //           UTF8String id:13
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.2 tcgTpmModel (TCPA/TCG Attribute)
        //           UTF8String NPCT6xx
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.1 tcgTpmManufacturer (TCPA/TCG Attribute)
        //           UTF8String id:FFFFF1D0
        var rootDeserializeResult = Asn1Deserializer.Deserialize(extension, AsnEncodingRules.DER);
        if (rootDeserializeResult.HasError)
        {
            values = null;
            return false;
        }

        if (rootDeserializeResult.Ok is null)
        {
            values = null;
            return false;
        }

        var asnRoot = rootDeserializeResult.Ok;
        byte[] tpmSpecSanRawSequence;
        // Certificate or serialNumber?
        if (asnRoot is AbstractAsn1Enumerable rootEnumerable)
        {
            // tbsCertificate present
            if (rootEnumerable.Items.Length == 1 && rootEnumerable.Items[0] is Asn1RawElement { Tag.TagClass: TagClass.ContextSpecific } nestedRoot)
            {
                var contextSpecificReader = new AsnReader(nestedRoot.RawValue, AsnEncodingRules.DER);
                var tpmSequenceReader = contextSpecificReader.ReadSetOf(contextSpecificReader.PeekTag());
                if (tpmSequenceReader.PeekTag() is { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Sequence or (int) UniversalTagNumber.Set })
                {
                    // serialNumber extract
                    tpmSpecSanRawSequence = tpmSequenceReader.ReadEncodedValue().ToArray();
                    if (tpmSequenceReader.HasData)
                    {
                        values = null;
                        return false;
                    }
                }
                else
                {
                    values = null;
                    return false;
                }
            }
            // serialNumber extract
            else if (rootEnumerable.Tag is { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Sequence or (int) UniversalTagNumber.Set })
            {
                tpmSpecSanRawSequence = extension;
            }
            else
            {
                values = null;
                return false;
            }
        }
        // tbsCertificate present
        else if (asnRoot is Asn1RawElement { Tag.TagClass: TagClass.ContextSpecific } nestedRoot)
        {
            var contextSpecificReader = new AsnReader(nestedRoot.RawValue, AsnEncodingRules.DER);
            var tpmSequenceReader = contextSpecificReader.ReadSetOf(contextSpecificReader.PeekTag());
            if (tpmSequenceReader.PeekTag() is { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Sequence or (int) UniversalTagNumber.Set })
            {
                // serialNumber extract
                tpmSpecSanRawSequence = tpmSequenceReader.ReadEncodedValue().ToArray();
                if (tpmSequenceReader.HasData)
                {
                    values = null;
                    return false;
                }
            }
            else
            {
                values = null;
                return false;
            }
        }
        else
        {
            values = null;
            return false;
        }

        var sanDeserializeResult = Asn1Deserializer.Deserialize(tpmSpecSanRawSequence, AsnEncodingRules.DER);
        if (sanDeserializeResult.HasError)
        {
            values = null;
            return false;
        }

        if (sanDeserializeResult.Ok is null)
        {
            values = null;
            return false;
        }

        if (sanDeserializeResult.Ok is not AbstractAsn1Enumerable tpmSpecSanSequence)
        {
            values = null;
            return false;
        }

        // go through all enumerable elements with 1 length
        while (tpmSpecSanSequence is { Items.Length: 1 } enumerable && enumerable.Items[0] is AbstractAsn1Enumerable innerEnumerable)
        {
            tpmSpecSanSequence = innerEnumerable;
        }

        var accumulator = new Dictionary<string, string>();
        foreach (var sanElement in tpmSpecSanSequence.Items)
        {
            if (sanElement is not AbstractAsn1Enumerable sanElementEnumerable)
            {
                continue;
            }

            // go through all enumerable elements with 1 length
            var currentElement = sanElementEnumerable;
            while (currentElement is { Items.Length: 1 } enumerable && enumerable.Items[0] is AbstractAsn1Enumerable innerEnumerable)
            {
                currentElement = innerEnumerable;
            }

            if (currentElement is { Items.Length: 2 } sanSetSeq)
            {
                if (sanSetSeq.Items[0] is Asn1ObjectIdentifier normalId && sanSetSeq.Items[1] is Asn1Utf8String normalValue)
                {
                    accumulator[normalId.Value] = normalValue.Value;
                }
                else if (sanSetSeq.Items[1] is Asn1ObjectIdentifier reverseOrderId && sanSetSeq.Items[0] is Asn1Utf8String reverseOrderValue)
                {
                    accumulator[reverseOrderId.Value] = reverseOrderValue.Value;
                }
            }
        }

        values = accumulator;
        return true;
    }

    /// <summary>
    ///     Verifies that the aikCert has an extended key usage extension and it contains OID 2.23.133.8.3.
    /// </summary>
    /// <param name="extensions">Extensions of the aikCert.</param>
    /// <returns><see langword="true" /> if the aikCert contains an extended key usage extension and it includes the OID 2.23.133.8.3, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool AikCertExtendedKeyUsageExists(X509ExtensionCollection extensions)
    {
        const string expectedEnhancedKeyUsage = "2.23.133.8.3";

        if (extensions is null)
        {
            return false;
        }

        foreach (var extension in extensions)
        {
            if (extension.Oid?.Value is "2.5.29.37" && extension is X509EnhancedKeyUsageExtension enhancedKeyUsageExtension)
            {
                foreach (var oid in enhancedKeyUsageExtension.EnhancedKeyUsages)
                {
                    if (oid.Value == expectedEnhancedKeyUsage)
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    ///     Verifies that the aikCert has a basic constraints extension and its CA component is set to false.
    /// </summary>
    /// <param name="extensions">Extensions of the aikCert.</param>
    /// <returns><see langword="true" /> if the aikCert has a basic constraints extension and its CA component is set to false, otherwise - <see langword="false" />.</returns>
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

    /// <summary>
    ///     Retrieves the aaguid from the certificate if it is present.
    /// </summary>
    /// <param name="aikCert">The AIK certificate used for the attestation, in X.509 encoding.</param>
    /// <returns>If the certificate has an aaguid - the result will contain a <see cref="Guid" />, if the certificate doesn't have an aaguid, the result will contain <see langword="null" />. Otherwise, it will indicate that an error occurred during the retrieval of the aaguid.</returns>
    protected virtual Result<Guid?> GetAaguidIfExists(X509Certificate2 aikCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (aikCert is null)
        {
            return Result<Guid?>.Fail();
        }

        // If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
        // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
        // Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
        var extension = aikCert.Extensions.FirstOrDefault(static x => x.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
        if (extension is not null)
        {
            if (extension.Critical)
            {
                return Result<Guid?>.Fail();
            }

            var deserializeResult = Asn1Deserializer.Deserialize(extension.RawData, AsnEncodingRules.BER);
            if (deserializeResult.HasError)
            {
                return Result<Guid?>.Fail();
            }

            if (deserializeResult.Ok is null)
            {
                return Result<Guid?>.Fail();
            }

            if (deserializeResult.Ok is not Asn1OctetString aaguidOctetString)
            {
                return Result<Guid?>.Fail();
            }

            if (aaguidOctetString.Value.Length != 16)
            {
                return Result<Guid?>.Fail();
            }

            var hexAaguid = Convert.ToHexString(aaguidOctetString.Value);
            var typedAaguid = new Guid(hexAaguid);
            return Result<Guid?>.Success(typedAaguid);
        }

        return Result<Guid?>.Success(null);
    }

    /// <summary>
    ///     If possible, converts the values contained in pubArea into the built-in .NET type <see cref="AsymmetricAlgorithm" />.
    /// </summary>
    /// <param name="pubArea">Decoded 'pubArea' (structure used by the TPM to represent the credential public key).</param>
    /// <param name="algorithm">Output parameter. If the conversion is successful and the method returns <see langword="true" />, it must not be null and should contain an instance of <see cref="AsymmetricAlgorithm" /> with data from <paramref name="pubArea" />.</param>
    /// <returns><see langword="true" /> if the conversion of <paramref name="pubArea" /> into <see cref="AsymmetricAlgorithm" /> was successful, otherwise - <see langword="false" />.</returns>
    protected virtual bool TryToAsymmetricAlgorithm(PubArea pubArea, [NotNullWhen(true)] out AsymmetricAlgorithm? algorithm)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (pubArea is null)
        {
            algorithm = null;
            return false;
        }

        switch (pubArea.Type)
        {
            case TpmAlgPublic.Rsa:
                {
                    if (pubArea.Unique is not RsaUnique tpmModulus)
                    {
                        algorithm = null;
                        return false;
                    }

                    if (pubArea.Parameters is not RsaParms tpmExponent)
                    {
                        algorithm = null;
                        return false;
                    }

                    var pubAreaExponent = new byte[4];
                    BinaryPrimitives.WriteUInt32BigEndian(pubAreaExponent, tpmExponent.Exponent);
                    var rsa = RSA.Create(new RSAParameters
                    {
                        Modulus = tpmModulus.Buffer,
                        Exponent = pubAreaExponent
                    });
                    algorithm = rsa;
                    return true;
                }
            case TpmAlgPublic.Ecc:
                {
                    if (pubArea.Unique is not EccUnique tpmEcPoint)
                    {
                        algorithm = null;
                        return false;
                    }

                    if (pubArea.Parameters is not EccParms tpmCurve)
                    {
                        algorithm = null;
                        return false;
                    }

                    if (!TryToEcCurve(tpmCurve.CurveId, out var ecCurve))
                    {
                        algorithm = null;
                        return false;
                    }

                    var point = new ECPoint
                    {
                        X = tpmEcPoint.X,
                        Y = tpmEcPoint.Y
                    };
                    var ecdsa = ECDsa.Create(new ECParameters
                    {
                        Q = point,
                        Curve = ecCurve.Value
                    });
                    algorithm = ecdsa;
                    return true;
                }
            default:
                {
                    algorithm = null;
                    return false;
                }
        }
    }

    /// <summary>
    ///     Calculates a hash for the passed value using the algorithm contained in the <paramref name="tpmAlg" />.
    /// </summary>
    /// <param name="tpmAlg">The algorithm that will be used to calculate the hash.</param>
    /// <param name="message">The message for which a hash needs to be calculated.</param>
    /// <param name="hash">The output parameter containing the calculated hash if the method returned <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns>If it's possible to calculate a hash for this particular algorithm - <see langword="true" /> (as well as the hash value itself in the output parameter <paramref name="hash" />), otherwise - <see langword="false" />.</returns>
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms")]
    protected virtual bool TryComputeHash(TpmAlgIdHash tpmAlg, byte[] message, [NotNullWhen(true)] out byte[]? hash)
    {
        switch (tpmAlg)
        {
            case TpmAlgIdHash.Sha1:
                {
                    hash = SHA1.HashData(message);
                    return true;
                }
            case TpmAlgIdHash.Sha256:
                {
                    hash = SHA256.HashData(message);
                    return true;
                }
            case TpmAlgIdHash.Sha384:
                {
                    hash = SHA384.HashData(message);
                    return true;
                }
            case TpmAlgIdHash.Sha512:
                {
                    hash = SHA512.HashData(message);
                    return true;
                }
            default:
                {
                    hash = null;
                    return false;
                }
        }
    }

    /// <summary>
    ///     Converts the elliptic curve specified in the <paramref name="tpmiEccCurve" /> from enum to a typed value, suitable for further use in digital signature computations using built-in .NET types.
    /// </summary>
    /// <param name="tpmiEccCurve">An enum containing the name of the elliptic curve that should be converted to a built-in .NET type.</param>
    /// <param name="crv">The output parameter containing the value of the elliptic curve, represented by a built-in .NET type, if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns>If such an elliptic curve is described using the ECCurve type - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool TryToEcCurve(TpmiEccCurve tpmiEccCurve, [NotNullWhen(true)] out ECCurve? crv)
    {
        switch (tpmiEccCurve)
        {
            case TpmiEccCurve.TpmEccNistP256:
                {
                    crv = ECCurve.NamedCurves.nistP256;
                    return true;
                }
            case TpmiEccCurve.TpmEccNistP384:
                {
                    crv = ECCurve.NamedCurves.nistP384;
                    return true;
                }
            case TpmiEccCurve.TpmEccNistP521:
                {
                    crv = ECCurve.NamedCurves.nistP521;
                    return true;
                }
            default:
                {
                    crv = null;
                    return false;
                }
        }
    }

    /// <summary>
    ///     Concatenates two ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
