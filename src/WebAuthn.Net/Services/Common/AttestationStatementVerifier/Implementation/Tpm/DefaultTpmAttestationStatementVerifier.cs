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
    // TCG EK Credential Profile for TPM Family 2.0, Level 0, Version 2.7, §3.1.2 "TPM Device Attributes":
    // tcg ::= { joint-iso-itu-t(2) international-organizations(23) tcg(133) }, tcg-attribute ::= { tcg 2 },
    // tcg-at-tpmManufacturer ::= { tcg-attribute 1 }, tcg-at-tpmModel ::= { tcg-attribute 2 }, tcg-at-tpmVersion ::= { tcg-attribute 3 }
    private const string TpmManufacturerOid = "2.23.133.2.1";
    private const string TpmModelOid = "2.23.133.2.2";
    private const string TpmVersionOid = "2.23.133.2.3";

    // RFC 5280 §4.1.2.6: an empty subject is an empty RDNSequence, i.e. an empty SEQUENCE in DER.
    private static ReadOnlySpan<byte> EmptyRdnSequence => "0\0"u8;

    // the (primitive, as DER requires) tag of the UTF8String values of the TPM device attributes
    private static readonly Asn1Tag Utf8StringTag = new(UniversalTagNumber.UTF8String);

    /// <summary>
    ///     Constructs <see cref="DefaultTpmAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="tpmPubAreaDecoder">
    ///     Decoder of the TPMT_PUBLIC structure, defined in the <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (Part 2 v185 §12.2.4, Table 235)</a>, from binary into a typed representation.
    /// </param>
    /// <param name="tpmCertInfoDecoder">
    ///     Decoder of the TPMS_ATTEST structure over which the attestation signature was computed, as specified in the
    ///     <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (Part 2 v185 §10.11.12; §10.12.8 in the rev 01.38 edition cited by WebAuthn L3)</a>.
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
    ///     Decoder of the TPMT_PUBLIC structure, defined in the <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (Part 2 v185 §12.2.4, Table 235)</a>, from binary into a typed representation.
    /// </summary>
    protected ITpmPubAreaDecoder TpmPubAreaDecoder { get; }

    /// <summary>
    ///     Decoder of the TPMS_ATTEST structure over which the attestation signature was computed, as specified in the
    ///     <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (Part 2 v185 §10.11.12; §10.12.8 in the rev 01.38 edition cited by WebAuthn L3)</a>.
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
        // https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
        // §8.3 "TPM Attestation Statement Format" - "Verification procedure"
        // (the steps below are quoted from "Web Authentication: An API for accessing Public Key Credentials Level 3", W3C Recommendation, 25 August 2026)
        // Given the verification procedure inputs attStmt, authenticatorData and clientDataHash, the verification procedure is as follows:

        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);

        // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // Performed by the attestation statement decoder (DefaultTpmAttestationStatementDecoder) that produced 'attStmt':
        // it enforces the tpmStmtFormat syntax, i.e. ver == "2.0", a COSEAlgorithmIdentifier in 'alg', and the presence and types of 'x5c', 'sig', 'certInfo' and 'pubArea'.

        // 2. Verify that the public key specified by the parameters and unique fields of pubArea
        // is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
        // 'pubArea' is the TPMT_PUBLIC structure (TPM 2.0 Library Part 2 v185 §12.2.4, Table 235) without the TPM2B_PUBLIC size prefix.
        var pubAreaResult = TpmPubAreaDecoder.Decode(attStmt.PubArea);
        if (pubAreaResult.HasError)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        var pubArea = pubAreaResult.Ok;
        if (!PubAreaKeySameAsAttestedCredentialData(pubArea, authenticatorData.AttestedCredentialData.CredentialPublicKey))
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 3. Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        var attToBeSigned = Concat(authenticatorData.Raw, clientDataHash);

        // 4. Verify integrity of certInfo
        // 5. Validate that certInfo is valid
        // 6. If successful, return implementation-specific values representing attestation type AttCA and attestation trust path x5c.
        return await ValidateCertInfoAsync(context, attStmt, authenticatorData, pubArea, attToBeSigned, cancellationToken);
    }

    /// <summary>
    ///     Verifies that the public key specified by the 'parameters' and 'unique' fields of 'pubArea' is identical to the 'credentialPublicKey' in the 'attestedCredentialData' in 'authenticatorData'.
    /// </summary>
    /// <param name="pubArea">Decoded 'pubArea' (structure used by the TPM to represent the credential public key).</param>
    /// <param name="authDataKey"><a href="https://www.w3.org/TR/webauthn-3/#credential-public-key">Credential public key</a> from <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> in COSE format.</param>
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
    ///     Performs steps 4 ("Verify integrity of certInfo"), 5 ("Validate that certInfo is valid") and 6 (return the attestation type AttCA and the attestation trust path x5c)
    ///     of the <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">TPM attestation statement verification procedure</a>.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attStmt">Decoded <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">TPM attestation statement</a>.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="pubArea">Decoded 'pubArea' (the TPMT_PUBLIC structure used by the TPM to represent the credential public key), already verified in step 2 to be identical to the credentialPublicKey.</param>
    /// <param name="attToBeSigned">The result of concatenating 'authenticatorData' and 'clientDataHash' to form 'attToBeSigned'.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the verification is successful - the result containing <see cref="VerifiedAttestationStatement" />, otherwise - the result indicating that the validation has failed.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual async Task<Result<VerifiedAttestationStatement>> ValidateCertInfoAsync(
        TContext context,
        TpmAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        PubArea pubArea,
        byte[] attToBeSigned,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (attStmt is null || authenticatorData is null || pubArea is null)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
        // §8.3 "TPM Attestation Statement Format" - "Verification procedure" (W3C Recommendation, 25 August 2026)

        // 4. Verify integrity of certInfo
        // 4.1 Verify that x5c is present.
        if (attStmt.X5C.Length == 0)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        var certificatesToDispose = new List<X509Certificate2>(attStmt.X5C.Length);
        try
        {
            // x5c: aikCert followed by its certificate chain, in X.509 encoding.
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
                // The validity period check is not a step of §8.3: it is a library policy applied by every attestation statement verifier in this library
                // (Packed, Android Key and TPM alike); the attestation trust path validator repeats it while building the chain.
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    return Result<VerifiedAttestationStatement>.Fail();
                }
            }

            var aikCert = x5CCertificates.First();

            // 4.2 Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.
            // https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements
            if (!IsTpmAttestationStatementCertificateRequirementsSatisfied(aikCert, out var manufacturerRootCertificates))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4.3 If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
            // verify that the value of this extension matches the aaguid in authenticatorData.
            var aaguidResult = GetAaguidIfExists(aikCert);
            if (aaguidResult.HasError)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (aaguidResult.Ok.HasValue && aaguidResult.Ok.Value != authenticatorData.AttestedCredentialData.Aaguid)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4.4 Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
            // NOTE: WebAuthn describes 'sig' as "a TPMT_SIGNATURE structure as specified in [TPMv2-Part2] section 11.3.4" (Part 2 v185 §11.3.6, Table 219),
            // but authenticators (Windows Hello), the FIDO conformance tools and interoperable relying-party libraries put the bare signature value there,
            // encoded per WebAuthn §6.5.6 "Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures"
            // (PKCS#1 v1.5 or PSS for RSA, a DER-encoded ECDSA-Sig-Value for ECDSA), and this library verifies it as such.
            // The signature covers the raw 'certInfo' bytes, i.e. the TPMS_ATTEST structure exactly as received.
            if (!SignatureVerifier.IsValidCertificateSign(aikCert, attStmt.Alg, attStmt.CertInfo, attStmt.Sig))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5. Validate that certInfo is valid:
            // Note: certInfo is a TPMS_ATTEST structure (TPM 2.0 Library Part 2 v185 §10.11.12, Table 154; §10.12.8 in the rev 01.38 edition cited by WebAuthn L3).
            // 5.1 Verify that magic is set to TPM_GENERATED_VALUE.
            // 5.2 Verify that type is set to TPM_ST_ATTEST_CERTIFY.
            // Both are enforced by ITpmCertInfoDecoder.Decode (DefaultTpmCertInfoDecoder): a TPMS_ATTEST whose 'magic' is not TPM_GENERATED_VALUE (0xff544347)
            // or whose 'type' is not TPM_ST_ATTEST_CERTIFY (0x8017) does not decode.
            var certInfoResult = TpmCertInfoDecoder.Decode(attStmt.CertInfo);
            if (certInfoResult.HasError)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var certInfo = certInfoResult.Ok;

            // 5.3 Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
            if (!attStmt.Alg.TryComputeHash(attToBeSigned, out var attToBeSignedHash))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!certInfo.ExtraData.AsSpan().SequenceEqual(attToBeSignedHash.AsSpan()))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5.4 Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3 (Part 2 v185 §10.11.3, Table 145),
            // whose name field contains a valid Name for pubArea, as computed using the procedure specified in [TPMv2-Part1] section 16
            // (Part 1 v185 clause 13 "Names", Table 9) using the nameAlg in the pubArea.
            // Note: The TPM will always return TPMS_CERTIFY_INFO structure with the same nameAlg in the name as the nameAlg in pubArea.
            // Part 1 v185 clause 13, Table 9: for a transient or persistent object Name := nameAlg || H_nameAlg(publicArea), where publicArea is the marshaled TPMT_PUBLIC
            // (reference implementation: Object.c, PublicMarshalAndComputeName / ObjectComputeName). WebAuthn's 'pubArea' is exactly that TPMT_PUBLIC
            // (the TPM2B_PUBLIC size prefix is removed), so the digest is computed over the raw 'attStmt.PubArea' bytes as received.
            // The TPM2B_NAME in 'attested.certify.name' must be a digest (neither a handle nor empty) whose hash algorithm equals pubArea.nameAlg.
            var name = certInfo.Attested.Certify.Name;
            if (name.Digest is null || name.Digest.HashAlg != pubArea.NameAlg)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // A nameAlg this library cannot compute (e.g. TPM_ALG_SM3_256) makes the Name unverifiable - fail closed.
            if (!TryComputeHash(pubArea.NameAlg, attStmt.PubArea, out var pubAreaHash) || !pubAreaHash.AsSpan().SequenceEqual(name.Digest.Digest.AsSpan()))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // Note: The remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2 (Part 1 v185 §28.2, Table 38),
            // i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored.
            // Depending on the properties of the aikCert key used, these fields may be obfuscated. If valid, these MAY be used as an input to risk engines.
            // Precisely: clockInfo.resetCount, clockInfo.restartCount and firmwareVersion are obfuscated (with a value derived from the signing key's Qualified Name)
            // when the AIK is not in the Endorsement or Platform hierarchy - TPM 2.0 Library Part 1 v185 §28.3, Part 3 v185 §18.1,
            // reference implementation Attest_spt.c (FillInAttestInfo); clockInfo.clock and clockInfo.safe are not obfuscated.

            // 6. If successful, return implementation-specific values representing attestation type AttCA and attestation trust path x5c.
            // The acceptable trust anchors are the embedded root certificates of the TPM manufacturer (see TpmRoots) and, when the FIDO Metadata Service
            // entry for the aaguid lists the "attca" attestation type, the root certificates of that entry.
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
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
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
    ///     Verifies that the AIK certificate used for the attestation satisfies the <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements">TPM attestation statement certificate requirements (section 8.3.1 of the WebAuthn specification)</a>, and also in
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

        // §8.3.1 "TPM Attestation Statement Certificate Requirements" (W3C Recommendation, 25 August 2026)
        // https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements
        // TPM attestation certificate MUST have the following fields/extensions:
        // 1) Version MUST be set to 3.
        if (aikCert.Version != 3)
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // 2) Subject field MUST be set to empty.
        // An empty subject is an empty RDNSequence, DER-encoded as an empty SEQUENCE (30 00) - RFC 5280 §4.1.2.6.
        // The DER of the name is compared directly instead of decoding SubjectName.Name: the X.500 string form is produced lazily and throws CryptographicException for a malformed name.
        if (!aikCert.SubjectName.RawData.AsSpan().SequenceEqual(EmptyRdnSequence))
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // 3) The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
        // TCG EK Credential Profile for TPM Family 2.0, Level 0, Version 2.7 (2026-03-16, PUBLISHED), §3.2.9 "Subject Alternative Name" and §3.1.2 "TPM Device Attributes":
        // https://cdn.trustedcomputinggroup.org/production/TCG_EK_Credential_Profile_for_TPM_Family_2_0_Level_0_Version_2_7_Pub_cafa3d55b0.pdf
        // (WebAuthn L3 cites Version 2.5 Revision 2; the SAN requirements are unchanged between the two editions.)
        // Note: Previous versions of [TPMv2-EK-Profile] allowed the inclusion of an optional attribute, called HardwareModuleName, that contains the TPM serial number
        // in the EK certificate. HardwareModuleName SHOULD NOT be placed in the attestation certificate Subject Alternative Name.
        // (A HardwareModuleName otherName, if present, is ignored by the SAN parser.)
        if (!TryGetAikCertSubjectAlternativeName(aikCert, out var san))
        {
            manufacturerRootCertificates = null;
            return false;
        }

        // The TPMManufacturer attribute must name a vendor from the TCG TPM Vendor ID Registry; the manufacturer verifier also supplies the embedded root certificates for that vendor.
        // Rejecting unknown manufacturers is a library policy, not a §8.3.1 requirement.
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
        if (aikCert is null)
        {
            san = null;
            return false;
        }

        // RawData of an X509Extension is the content of the extnValue OCTET STRING, i.e. the DER-encoded GeneralNames.
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

        if (!values.TryGetValue(TpmManufacturerOid, out var manufacturer))
        {
            san = null;
            return false;
        }

        if (!values.TryGetValue(TpmModelOid, out var model))
        {
            san = null;
            return false;
        }

        if (!values.TryGetValue(TpmVersionOid, out var version))
        {
            san = null;
            return false;
        }

        san = new(manufacturer, model, version);
        return true;
    }

    /// <summary>
    ///     Decodes the value of the Subject Alternative Name (SAN) certificate extension and extracts the TPM device attributes (TPMManufacturer, TPMModel and TPMVersion) from its directoryName.
    /// </summary>
    /// <param name="extension">The value of the Subject Alternative Name (SAN) certificate extension: the content of the extnValue OCTET STRING, i.e. DER-encoded GeneralNames.</param>
    /// <param name="values">
    ///     Output parameter. If the method returns <see langword="true" /> - it must not be <see langword="null" /> and contains the TPM device attributes as a dictionary keyed by the attribute type OID
    ///     (2.23.133.2.1 - TPMManufacturer, 2.23.133.2.2 - TPMModel, 2.23.133.2.3 - TPMVersion).
    /// </param>
    /// <returns><see langword="true" /> if the extension is a well-formed GeneralNames with a directoryName that carries all three TPM device attributes as UTF8Strings without conflicting duplicates, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryParseSanExtensionValues(byte[] extension, [NotNullWhen(true)] out Dictionary<string, string>? values)
    {
        // RFC 5280 §4.2.1.6 "Subject Alternative Name":
        // SubjectAltName ::= GeneralNames
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        // GeneralName ::= CHOICE {
        //     otherName                 [0] OtherName,
        //     rfc822Name                [1] IA5String,
        //     dNSName                   [2] IA5String,
        //     x400Address               [3] ORAddress,
        //     directoryName             [4] Name,
        //     ediPartyName              [5] EDIPartyName,
        //     uniformResourceIdentifier [6] IA5String,
        //     iPAddress                 [7] OCTET STRING,
        //     registeredID              [8] OBJECT IDENTIFIER }
        // Name is a CHOICE, so directoryName [4] is EXPLICITLY tagged: a constructed context-specific [4] element that wraps the complete Name encoding.
        // ITU-T X.501 / RFC 5280 §4.1.2.4:
        // Name ::= CHOICE { rdnSequence RDNSequence }
        // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
        // RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
        // AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }
        // AttributeType ::= OBJECT IDENTIFIER
        // AttributeValue ::= ANY -- DEFINED BY AttributeType
        //
        // TCG EK Credential Profile for TPM Family 2.0, Level 0, Version 2.7 (2026-03-16), §3.2.9 "Subject Alternative Name":
        // "The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryName-form within the GeneralName structure."
        // §3.1.2 "TPM Device Attributes" (ASN.1 module):
        // TPMManufacturer ATTRIBUTE ::= { WITH SYNTAX UTF8String (SIZE (1..STRMAX)) ID tcg-at-tpmManufacturer } -- 2.23.133.2.1, "id:" + 8 uppercase hex digits of the TCG vendor ID (e.g. id:414D4400)
        // TPMModel        ATTRIBUTE ::= { WITH SYNTAX UTF8String (SIZE (1..STRMAX)) ID tcg-at-tpmModel }        -- 2.23.133.2.2, vendor-specific part number (e.g. AMD)
        // TPMVersion      ATTRIBUTE ::= { WITH SYNTAX UTF8String (SIZE (1..STRMAX)) ID tcg-at-tpmVersion }      -- 2.23.133.2.3, "id:" + 8 uppercase hex digits of the firmware version (e.g. id:00030001)
        // The values MUST be UTF8String; other string types are not accepted here.
        //
        // Encodings seen in the wild (all handled by the strict walk below, which accepts any number of attributes per RDN and any order of RDNs and attributes):
        // (1) EK Credential Profile Appendix A example and the Windows Hello / AMD fTPM AIK certificates - three single-valued RDNs:
        //     SEQUENCE (GeneralNames)
        //       [4] (directoryName, constructed)
        //         SEQUENCE (RDNSequence)
        //           SET { SEQUENCE { OBJECT IDENTIFIER 2.23.133.2.1, UTF8String "id:414D4400" } }
        //           SET { SEQUENCE { OBJECT IDENTIFIER 2.23.133.2.2, UTF8String "AMD" } }
        //           SET { SEQUENCE { OBJECT IDENTIFIER 2.23.133.2.3, UTF8String "id:00030001" } }
        // (2) FIDO conformance tools - one RDN holding all three attributes in reverse order (which is also the DER sort order of these particular values):
        //     SEQUENCE (GeneralNames)
        //       [4] (directoryName, constructed)
        //         SEQUENCE (RDNSequence)
        //           SET {
        //             SEQUENCE { OBJECT IDENTIFIER 2.23.133.2.3, UTF8String "id:13" }
        //             SEQUENCE { OBJECT IDENTIFIER 2.23.133.2.2, UTF8String "NPCT6xx" }
        //             SEQUENCE { OBJECT IDENTIFIER 2.23.133.2.1, UTF8String "id:FFFFF1D0" } }
        // (3) additional GeneralNames before or after the directoryName, e.g. the legacy HardwareModuleName otherName ([0], type-id 1.3.6.1.5.5.7.8.4)
        //     that EK Credential Profile versions before 2.1 allowed and WebAuthn says SHOULD NOT be present - every GeneralName other than directoryName is ignored.
        //
        // The walk is exception-free and DER-strict: every element is located with AsnDecoder.TryReadEncodedValue (definite, minimal lengths), the SET OF is validated with
        // AsnDecoder.ReadSetOf (DER sort order) and the leaves are decoded with AsnDecoder.ReadObjectIdentifier / ReadCharacterString, with AsnContentException turned into 'false'.
        // The generic IAsn1Deserializer tree is not used here because the EXPLICIT [4] wrapper and the SET OF ordering rule are easier to validate directly on the encoding.
        values = null;
        if (extension is null)
        {
            return false;
        }

        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        if (!TryReadElement(extension, out var generalNamesTag, out var generalNames, out var generalNamesLength)
            || generalNamesLength != extension.Length
            || generalNamesTag != Asn1Tag.Sequence
            || generalNames.IsEmpty)
        {
            return false;
        }

        var accumulator = new Dictionary<string, string>(3, StringComparer.Ordinal);
        while (!generalNames.IsEmpty)
        {
            if (!TryReadElement(generalNames, out var generalNameTag, out var generalName, out var generalNameLength))
            {
                return false;
            }

            // only directoryName [4] carries the TPM device attributes; every other GeneralName alternative is ignored
            if (generalNameTag.TagClass == TagClass.ContextSpecific && generalNameTag.TagValue == 4)
            {
                // EXPLICIT tagging: a primitive [4] cannot wrap a Name
                if (!generalNameTag.IsConstructed || !TryCollectTpmDeviceAttributes(generalName, accumulator))
                {
                    return false;
                }
            }

            generalNames = generalNames[generalNameLength..];
        }

        if (!accumulator.ContainsKey(TpmManufacturerOid) || !accumulator.ContainsKey(TpmModelOid) || !accumulator.ContainsKey(TpmVersionOid))
        {
            return false;
        }

        values = accumulator;
        return true;
    }

    /// <summary>
    ///     Walks the content of a directoryName GeneralName (an EXPLICITLY tagged [4] Name) and collects the TPM device attributes of its RDNSequence into <paramref name="accumulator" />.
    /// </summary>
    /// <param name="name">The content of the directoryName element: the complete encoding of the Name (RDNSequence).</param>
    /// <param name="accumulator">The TPM device attributes collected so far, keyed by the attribute type OID.</param>
    /// <returns><see langword="true" /> if the content is a well-formed RDNSequence whose TPM device attributes are UTF8Strings that do not conflict with already collected values, otherwise - <see langword="false" />.</returns>
    private static bool TryCollectTpmDeviceAttributes(ReadOnlySpan<byte> name, Dictionary<string, string> accumulator)
    {
        // Name ::= CHOICE { rdnSequence RDNSequence }
        // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName - the [4] wrapper must contain exactly one element, the RDNSequence
        if (!TryReadElement(name, out var rdnSequenceTag, out var rdnSequence, out var rdnSequenceLength)
            || rdnSequenceLength != name.Length
            || rdnSequenceTag != Asn1Tag.Sequence)
        {
            return false;
        }

        while (!rdnSequence.IsEmpty)
        {
            // RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
            if (!TryReadSetOf(rdnSequence, out var relativeDistinguishedName, out var relativeDistinguishedNameLength) || relativeDistinguishedName.IsEmpty)
            {
                return false;
            }

            rdnSequence = rdnSequence[relativeDistinguishedNameLength..];
            while (!relativeDistinguishedName.IsEmpty)
            {
                // AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY DEFINED BY type }
                if (!TryReadElement(relativeDistinguishedName, out var attributeTypeAndValueTag, out var attributeTypeAndValue, out var attributeTypeAndValueLength)
                    || attributeTypeAndValueTag != Asn1Tag.Sequence)
                {
                    return false;
                }

                relativeDistinguishedName = relativeDistinguishedName[attributeTypeAndValueLength..];
                if (!TryReadObjectIdentifier(attributeTypeAndValue, out var attributeType, out var attributeTypeLength))
                {
                    return false;
                }

                // exactly one value element and nothing after it
                var attributeValue = attributeTypeAndValue[attributeTypeLength..];
                if (!TryReadElement(attributeValue, out var attributeValueTag, out _, out var attributeValueLength) || attributeValueLength != attributeValue.Length)
                {
                    return false;
                }

                if (!TryCollectTpmDeviceAttribute(attributeType, attributeValueTag, attributeValue, accumulator))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    ///     Adds a TPM device attribute to <paramref name="accumulator" />; attributes of any other type are ignored.
    /// </summary>
    /// <param name="attributeType">The attribute type OID.</param>
    /// <param name="attributeValueTag">The tag of the attribute value element.</param>
    /// <param name="attributeValue">The complete encoding of the attribute value element.</param>
    /// <param name="accumulator">The TPM device attributes collected so far, keyed by the attribute type OID.</param>
    /// <returns><see langword="false" /> if the attribute is a TPM device attribute whose value is not a UTF8String or differs from an already collected value of the same type, otherwise - <see langword="true" />.</returns>
    private static bool TryCollectTpmDeviceAttribute(string attributeType, Asn1Tag attributeValueTag, ReadOnlySpan<byte> attributeValue, Dictionary<string, string> accumulator)
    {
        if (attributeType is not (TpmManufacturerOid or TpmModelOid or TpmVersionOid))
        {
            // e.g. a serial number (EK Credential Profile 2.7 §3.2.6) - not needed by WebAuthn
            return true;
        }

        // TCG EK Credential Profile 2.7 §3.1.2: TPMManufacturer, TPMModel and TPMVersion are UTF8String (SIZE (1..STRMAX)); other string types are not accepted.
        if (attributeValueTag != Utf8StringTag)
        {
            return false;
        }

        string value;
        try
        {
            value = AsnDecoder.ReadCharacterString(attributeValue, AsnEncodingRules.DER, UniversalTagNumber.UTF8String, out _);
        }
        catch (AsnContentException)
        {
            // not valid UTF-8
            return false;
        }

        if (accumulator.TryGetValue(attributeType, out var existingValue))
        {
            // an identical duplicate is tolerated, a conflicting one is not
            return string.Equals(existingValue, value, StringComparison.Ordinal);
        }

        accumulator.Add(attributeType, value);
        return true;
    }

    /// <summary>
    ///     Reads the tag, length and content of the first DER element of <paramref name="source" /> without throwing.
    /// </summary>
    /// <param name="source">The bytes to read from.</param>
    /// <param name="tag">The tag of the element.</param>
    /// <param name="content">The content octets of the element.</param>
    /// <param name="bytesConsumed">The total number of octets of the element (tag, length and content).</param>
    /// <returns><see langword="true" /> if a well-formed DER element starts at the beginning of <paramref name="source" />, otherwise - <see langword="false" />.</returns>
    private static bool TryReadElement(ReadOnlySpan<byte> source, out Asn1Tag tag, out ReadOnlySpan<byte> content, out int bytesConsumed)
    {
        if (AsnDecoder.TryReadEncodedValue(source, AsnEncodingRules.DER, out tag, out var contentOffset, out var contentLength, out bytesConsumed))
        {
            content = source.Slice(contentOffset, contentLength);
            return true;
        }

        content = default;
        return false;
    }

    /// <summary>
    ///     Reads the content of the SET OF element at the beginning of <paramref name="source" /> without throwing; the DER sort order of its elements is verified.
    /// </summary>
    /// <param name="source">The bytes to read from.</param>
    /// <param name="content">The content octets of the SET OF.</param>
    /// <param name="bytesConsumed">The total number of octets of the element (tag, length and content).</param>
    /// <returns><see langword="true" /> if a well-formed SET OF starts at the beginning of <paramref name="source" />, otherwise - <see langword="false" />.</returns>
    private static bool TryReadSetOf(ReadOnlySpan<byte> source, out ReadOnlySpan<byte> content, out int bytesConsumed)
    {
        try
        {
            AsnDecoder.ReadSetOf(source, AsnEncodingRules.DER, out var contentOffset, out var contentLength, out bytesConsumed);
            content = source.Slice(contentOffset, contentLength);
            return true;
        }
        catch (AsnContentException)
        {
            content = default;
            bytesConsumed = 0;
            return false;
        }
    }

    /// <summary>
    ///     Reads the OBJECT IDENTIFIER element at the beginning of <paramref name="source" /> without throwing.
    /// </summary>
    /// <param name="source">The bytes to read from.</param>
    /// <param name="objectIdentifier">The decoded object identifier in dotted-decimal notation.</param>
    /// <param name="bytesConsumed">The total number of octets of the element (tag, length and content).</param>
    /// <returns><see langword="true" /> if a well-formed OBJECT IDENTIFIER starts at the beginning of <paramref name="source" />, otherwise - <see langword="false" />.</returns>
    private static bool TryReadObjectIdentifier(ReadOnlySpan<byte> source, [NotNullWhen(true)] out string? objectIdentifier, out int bytesConsumed)
    {
        try
        {
            objectIdentifier = AsnDecoder.ReadObjectIdentifier(source, AsnEncodingRules.DER, out bytesConsumed);
            return true;
        }
        catch (AsnContentException)
        {
            objectIdentifier = null;
            bytesConsumed = 0;
            return false;
        }
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
                OidCollection enhancedKeyUsages;
                try
                {
                    // The extension body is decoded lazily on first access; a malformed ExtKeyUsageSyntax throws CryptographicException.
                    enhancedKeyUsages = enhancedKeyUsageExtension.EnhancedKeyUsages;
                }
                catch (CryptographicException)
                {
                    return false;
                }

                foreach (var oid in enhancedKeyUsages)
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
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool IsBasicExtensionsCaComponentFalse(X509ExtensionCollection extensions)
    {
        if (extensions is null)
        {
            return false;
        }

        // The Basic Constraints extension MUST have the CA component set to false.
        var extension = extensions.FirstOrDefault(static e => e.Oid?.Value is "2.5.29.19");
        if (extension is X509BasicConstraintsExtension basicExtension)
        {
            try
            {
                // The extension body is decoded lazily on first access; a malformed BasicConstraints body throws CryptographicException.
                var isCaCert = basicExtension.CertificateAuthority;
                return !isCaCert;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        return false;
    }

    /// <summary>
    ///     Retrieves the aaguid from the certificate if it is present.
    /// </summary>
    /// <param name="aikCert">The AIK certificate used for the attestation, in X.509 encoding.</param>
    /// <returns>
    ///     If the certificate has an aaguid - the result will contain a <see cref="Guid" />, if the certificate doesn't have an aaguid, the result will contain <see langword="null" />.
    ///     Otherwise, it will indicate that an error occurred during the retrieval of the aaguid.
    /// </returns>
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

            // The extension value must be exactly one primitive OCTET STRING (the inner wrapper of the AAGUID); anything else is rejected before it reaches the deserializer.
            if (!AsnDecoder.TryReadEncodedValue(extension.RawData, AsnEncodingRules.BER, out var aaguidTag, out _, out _, out var aaguidBytesConsumed)
                || aaguidBytesConsumed != extension.RawData.Length
                || !aaguidTag.HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
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

                    // TPMS_RSA_PARMS.exponent is a UINT32 (the decoder has already replaced the wire value 0 with the default 2^16 + 1).
                    // RSAParameters.Exponent and the COSE 'e' parameter (RFC 8230 §4) are the unsigned big-endian integer without leading zero octets (65537 -> 01 00 01);
                    // the minimal encoding makes the exponent exported by RSA.Create identical on every platform and byte-comparable with the COSE key.
                    var pubAreaExponent = ToMinimalUnsignedBigEndian(tpmExponent.Exponent);
                    try
                    {
                        // An unusable modulus or exponent throws on some platforms (CNG and Apple's SecKey validate the key on import) - fail instead of propagating.
                        algorithm = RSA.Create(new RSAParameters
                        {
                            Modulus = tpmModulus.Buffer,
                            Exponent = pubAreaExponent
                        });
                        return true;
                    }
                    catch (CryptographicException)
                    {
                        algorithm = null;
                        return false;
                    }
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
                    try
                    {
                        // The decoder guarantees that both coordinates have the size of the curve, but a point that is not on the curve still throws
                        // CryptographicException on import (OpenSSL EC_KEY_check_key, CNG, Apple's SecKey) - fail instead of propagating.
                        algorithm = ECDsa.Create(new ECParameters
                        {
                            Q = point,
                            Curve = ecCurve.Value
                        });
                        return true;
                    }
                    catch (CryptographicException)
                    {
                        algorithm = null;
                        return false;
                    }
                }
            default:
                {
                    algorithm = null;
                    return false;
                }
        }
    }

    /// <summary>
    ///     Encodes an unsigned 32-bit integer as its shortest big-endian byte representation (no leading zero octets, at least one octet) -
    ///     the encoding of the public exponent in <see cref="RSAParameters" /> and in COSE RSA keys.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The minimal unsigned big-endian representation of <paramref name="value" />.</returns>
    private static byte[] ToMinimalUnsignedBigEndian(uint value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        var leadingZeros = 0;
        while (leadingZeros < buffer.Length - 1 && buffer[leadingZeros] == 0)
        {
            leadingZeros++;
        }

        return buffer[leadingZeros..].ToArray();
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
        // TpmAlgIdHash lists every TPMI_ALG_HASH identifier (TPM 2.0 Library Part 2 v185, Table 77); only the SHA-1 / SHA-2 family is computed here.
        // SHA-1 is kept because deployed Windows TPM AIK chains still use it; SHA256_192, SM3_256, SHA3-* and SHAKE256-* are reported as not computable (fail closed).
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
