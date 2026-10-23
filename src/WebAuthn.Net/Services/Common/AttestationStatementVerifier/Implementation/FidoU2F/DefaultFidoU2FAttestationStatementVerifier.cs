using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.FidoU2F;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService.Enums;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F;

/// <summary>
///     Default implementation of <see cref="IFidoU2FAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultFidoU2FAttestationStatementVerifier<TContext>
    : IFidoU2FAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoU2FAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="asn1Deserializer">ASN.1 format deserializer.</param>
    /// <param name="fidoMetadataSearchService">A service for searching in the data provided by the FIDO Metadata Service.</param>
    /// <param name="counters">Counters for registration ceremony metrics, used to count the anomalies found while verifying the attestation statement.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoU2FAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IAsn1Deserializer asn1Deserializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService,
        IRegistrationCeremonyCounters counters,
        ILogger<DefaultFidoU2FAttestationStatementVerifier<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(asn1Deserializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        TimeProvider = timeProvider;
        Asn1Deserializer = asn1Deserializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     ASN.1 format deserializer.
    /// </summary>
    protected IAsn1Deserializer Asn1Deserializer { get; }

    /// <summary>
    ///     A service for searching in the data provided by the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    /// <summary>
    ///     Counters for registration ceremony metrics, used to count the anomalies found while verifying the attestation statement
    ///     (see <see cref="FidoU2FAttestationStatementAnomalies" />).
    /// </summary>
    protected IRegistrationCeremonyCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultFidoU2FAttestationStatementVerifier<TContext>> Logger { get; }

    /// <inheritdoc />
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        FidoU2FAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation
        // "FIDO U2F Attestation Statement Format"

        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();

        // 1) Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Check that 'x5c' has exactly one element and let 'attCert' be that element.
        // Let certificate public key be the public key conveyed by 'attCert'.
        // If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.

        if (attStmt.X5C.Length != 1)
        {
            Logger.FidoU2FX5CNotSingleElement(attStmt.X5C.Length);
            return Result<VerifiedAttestationStatement>.Fail();
        }

        X509Certificate2? attCert = null;
        try
        {
            var rawAttCert = attStmt.X5C[0];

            if (!X509CertificateInMemoryLoader.TryLoad(rawAttCert, out attCert))
            {
                attCert?.Dispose();
                Logger.FidoU2FAttCertInvalid();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            if (currentDate < attCert.NotBefore || currentDate > attCert.NotAfter)
            {
                Logger.FidoU2FAttCertNotValidNow();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!IsValidPublicKeyParameters(attCert, out var attCertEcParameters))
            {
                Logger.FidoU2FAttCertPublicKeyNotP256();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 3) Extract the claimed 'rpIdHash' from 'authenticatorData', and the claimed 'credentialId' and 'credentialPublicKey'
            // from 'authenticatorData.attestedCredentialData'.
            var rpIdHash = authenticatorData.RpIdHash;
            var credentialId = authenticatorData.AttestedCredentialData.CredentialId;
            if (authenticatorData.AttestedCredentialData.CredentialPublicKey is not CoseEc2Key credentialPublicKey)
            {
                Logger.FidoU2FCredentialPublicKeyNotEc2();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4) Convert the COSE_KEY formatted 'credentialPublicKey' (see Section 7 of [RFC9052])
            // to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
            if (!TryConvertCoseKeyToPublicKeyU2F(credentialPublicKey, out var publicKeyU2F))
            {
                Logger.FidoU2FCredentialPublicKeyCoordinatesInvalid(credentialPublicKey.X.Length, credentialPublicKey.Y.Length);
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5) Let 'verificationData' be the concatenation of
            // (0x00 || 'rpIdHash' || 'clientDataHash' || 'credentialId' || 'publicKeyU2F') (see Section 4.3 of [FIDO-U2F-Message-Formats]).
            var verificationData = Concat(stackalloc byte[1] { 0x00 }, rpIdHash, clientDataHash, credentialId, publicKeyU2F);

            // 6) Verify the 'sig' using 'verificationData' and the certificate public key per section 4.1.4 of [SEC1]
            // with SHA-256 as the hash function used in step two.
            if (!IsValidSignature(attCertEcParameters.Value, verificationData, attStmt.Sig))
            {
                Logger.FidoU2FSignatureInvalid();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // The 'aaguid' of 'authenticatorData' is not part of 'verificationData', so the attestation signature doesn't cover it: unlike in the other attestation statement formats,
            // it is not attested here, and the authenticator model is identified by 'attCert' only (step 7). The only attested aaguid is the one of the id-fido-gen-ce-aaguid extension of 'attCert'.
            // Like the 'packed' (§8.2) and 'tpm' (§8.3) verification procedures, and as §13.3.1 intends ("so that it can be verified against the authenticator data"),
            // a non-zero 'aaguid' in 'authenticatorData' that differs from the extension rejects the attestation statement. A zero 'aaguid' is what a client reports for a CTAP1/U2F authenticator.
            var aaguidExtensionResult = GetAaguidIfExists(attCert);
            if (aaguidExtensionResult.HasError)
            {
                Logger.FidoU2FAttCertAaguidExtensionInvalid();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var aaguidExtension = aaguidExtensionResult.Ok;
            var authenticatorDataAaguid = authenticatorData.AttestedCredentialData.Aaguid;
            if (aaguidExtension.HasValue && authenticatorDataAaguid != Guid.Empty && authenticatorDataAaguid != aaguidExtension.Value)
            {
                Logger.FidoU2FAuthenticatorDataAaguidMismatch(authenticatorDataAaguid, aaguidExtension.Value);
                Counters.IncrementAttestationStatementAnomaly(FidoU2FAttestationStatementAnomalies.Format, FidoU2FAttestationStatementAnomalies.AuthenticatorDataAaguidMismatch, false);
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 7) Optionally, inspect 'x5c' and consult externally provided knowledge to determine whether 'attStmt' conveys a Basic or AttCA attestation.
            // (GetAttestationTypeAsync logs why the attestation type could not be determined)
            var attestationTypeResult = await GetAttestationTypeAsync(
                context,
                attCert,
                aaguidExtension,
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

    /// <summary>
    ///     Verifies the 'sig' using 'verificationData' and the certificate public key per section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
    /// </summary>
    /// <param name="attCertEcParameters">The P-256 public key parameters of the attestation certificate.</param>
    /// <param name="verificationData">The data over which the signature was calculated.</param>
    /// <param name="sig">The <a href="https://www.w3.org/TR/webauthn-3/#attestation-signature">attestation signature</a>, a DER-encoded ECDSA-Sig-Value.</param>
    /// <returns><see langword="true" /> if the signature is valid, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsValidSignature(ECParameters attCertEcParameters, ReadOnlySpan<byte> verificationData, byte[] sig)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (sig is null)
        {
            return false;
        }

        try
        {
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new()
                {
                    X = attCertEcParameters.Q.X,
                    Y = attCertEcParameters.Q.Y
                }
            });
            return ecdsa.VerifyData(verificationData, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            // the key and the signature come from the client: a point the platform refuses or a signature it cannot parse is a verification failure, not an exception
            return false;
        }
    }

    /// <summary>
    ///     Returns the <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">attestation type</a> of the <a href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a>.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="aaguidExtension">The aaguid from the id-fido-gen-ce-aaguid extension of the <paramref name="attCert" />, or <see langword="null" /> if it has no such extension.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If the <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">attestation type</a> was successfully determined and a list of Root CA certificates was obtained, the result contains a <see cref="FidoU2FAttestationTypeResult" />. Otherwise, the
    ///     result indicates that an error occurred during the execution of this operation.
    /// </returns>
    protected virtual async Task<Result<FidoU2FAttestationTypeResult>> GetAttestationTypeAsync(
        TContext context,
        X509Certificate2 attCert,
        Guid? aaguidExtension,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadataResult = await FindFidoMetadataAsync(context, attCert, aaguidExtension, cancellationToken);
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

        Logger.FidoU2FMetadataAttestationTypesNotSupported();
        return Result<FidoU2FAttestationTypeResult>.Fail();
    }

    /// <summary>
    ///     Searches for data in the FIDO Metadata Service.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         WebAuthn L3 §8.6 step 7 determines the attestation type by inspecting 'x5c' and consulting externally provided knowledge, so the authenticator model is identified by the <paramref name="attCert" /> only:
    ///         the metadata is looked up by the <paramref name="aaguidExtension" /> (if the <paramref name="attCert" /> has one), then by the key identifier of the <paramref name="attCert" />
    ///         (<a href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2">RFC 5280 §4.2.1.2</a> method (1)), and then by the value of its Subject Key Identifier extension (if it has one that differs from the key identifier).
    ///         The aaguid of the authenticator data is never used: the FIDO U2F attestation signature doesn't cover it, so any client could report the aaguid of another authenticator model.
    ///     </para>
    ///     <para>
    ///         The next lookup is performed only if there is no usable entry for the previous one (<see cref="FidoMetadataSearchError.NotFound" />). An entry that doesn't allow to trust the authenticator
    ///         (<see cref="FidoMetadataSearchError.Untrusted" />) rejects the attestation statement, and so does the absence of any metadata (<see cref="FidoMetadataSearchError.MetadataNotAvailable" />), with which no other lookup can succeed.
    ///     </para>
    /// </remarks>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="aaguidExtension">The aaguid from the id-fido-gen-ce-aaguid extension of the <paramref name="attCert" />, or <see langword="null" /> if it has no such extension.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If data was found, the result contains a <see cref="FidoMetadataResult" />. Otherwise, the result indicates that the data was not found, that the FIDO Metadata Service doesn't allow to trust the authenticator,
    ///     or that an error occurred during the process.
    /// </returns>
    protected virtual async Task<Result<FidoMetadataResult>> FindFidoMetadataAsync(
        TContext context,
        X509Certificate2 attCert,
        Guid? aaguidExtension,
        CancellationToken cancellationToken)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attCert is null)
        {
            return Result<FidoMetadataResult>.Fail();
        }

        if (aaguidExtension.HasValue)
        {
            var aaguidExtensionMetadata = await FidoMetadataSearchService.FindMetadataByAaguidAsync(
                context,
                aaguidExtension.Value,
                cancellationToken);
            if (!aaguidExtensionMetadata.HasError)
            {
                return Result<FidoMetadataResult>.Success(aaguidExtensionMetadata.Ok);
            }

            // an entry that doesn't allow to trust the authenticator is decisive: the attestation statement is rejected without looking for another entry
            if (aaguidExtensionMetadata.Error is FidoMetadataSearchError.Untrusted)
            {
                Logger.FidoU2FMetadataUntrustedByAaguid(aaguidExtension.Value);
                return Result<FidoMetadataResult>.Fail();
            }

            // without any metadata the lookups by the key identifier can't succeed either; only when there is no usable entry for the aaguid,
            // the attestation certificate is looked up by its key identifier, because the metadata may list it in 'attestationCertificateKeyIdentifiers'
            if (aaguidExtensionMetadata.Error is not FidoMetadataSearchError.NotFound)
            {
                Logger.FidoU2FMetadataNotFoundByAaguid(aaguidExtension.Value);
                return Result<FidoMetadataResult>.Fail();
            }
        }

        // FIDO Metadata Statement §3.1: 'attestationCertificateKeyIdentifiers' - "A list of the attestation certificate public key identifiers encoded as hex string.
        // This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in [RFC5280] section 4.2.1.2."
        // The identifier is a hash of the public key, so it is computed from the certificate itself (the attestation certificates of U2F authenticators usually carry no Subject Key Identifier extension);
        // the value of a Subject Key Identifier extension, if there is one, is tried as a fallback (it is normally the same hash, but a vendor may have used another method).
        if (!TryComputeAttestationCertificateKeyIdentifier(attCert, out var computedKeyIdentifier))
        {
            Logger.FidoU2FAttCertKeyIdentifierNotComputable();
            return Result<FidoMetadataResult>.Fail();
        }

        var computedKeyIdentifierMetadata = await FidoMetadataSearchService.FindMetadataBySubjectKeyIdentifierAsync(
            context,
            computedKeyIdentifier,
            cancellationToken);
        if (!computedKeyIdentifierMetadata.HasError)
        {
            return Result<FidoMetadataResult>.Success(computedKeyIdentifierMetadata.Ok);
        }

        // an entry that doesn't allow to trust the authenticator is decisive: the attestation statement is rejected without looking for another entry
        if (computedKeyIdentifierMetadata.Error is FidoMetadataSearchError.Untrusted)
        {
            Logger.FidoU2FMetadataUntrustedByKeyIdentifier(Convert.ToHexString(computedKeyIdentifier));
            return Result<FidoMetadataResult>.Fail();
        }

        // without any metadata the lookup by the value of the Subject Key Identifier extension can't succeed either
        if (computedKeyIdentifierMetadata.Error is FidoMetadataSearchError.NotFound)
        {
            var embeddedSkiResult = GetSubjectKeyIdentifierIfExists(attCert);
            if (embeddedSkiResult.HasError)
            {
                return Result<FidoMetadataResult>.Fail();
            }

            var embeddedSki = embeddedSkiResult.Ok;
            if (embeddedSki is not null && !embeddedSki.AsSpan().SequenceEqual(computedKeyIdentifier))
            {
                var embeddedSkiMetadata = await FidoMetadataSearchService.FindMetadataBySubjectKeyIdentifierAsync(
                    context,
                    embeddedSki,
                    cancellationToken);
                if (!embeddedSkiMetadata.HasError)
                {
                    return Result<FidoMetadataResult>.Success(embeddedSkiMetadata.Ok);
                }

                if (embeddedSkiMetadata.Error is FidoMetadataSearchError.Untrusted)
                {
                    Logger.FidoU2FMetadataUntrustedByKeyIdentifier(Convert.ToHexString(embeddedSki));
                    return Result<FidoMetadataResult>.Fail();
                }
            }
        }

        if (aaguidExtension.HasValue)
        {
            Logger.FidoU2FMetadataNotFoundByAaguidAndKeyIdentifier(aaguidExtension.Value, Convert.ToHexString(computedKeyIdentifier));
        }
        else
        {
            Logger.FidoU2FMetadataNotFoundByKeyIdentifier(Convert.ToHexString(computedKeyIdentifier));
        }

        return Result<FidoMetadataResult>.Fail();
    }

    /// <summary>
    ///     Computes the attestation certificate key identifier used by the FIDO Metadata Service ('attestationCertificateKeyIdentifiers'): the keyIdentifier of method (1) of
    ///     <a href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2">RFC 5280 §4.2.1.2</a>, i.e. the 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey (excluding the tag, length, and number of unused bits).
    /// </summary>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="keyIdentifier">Output parameter. If the method returns <see langword="true" /> - the 20-byte key identifier, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the identifier was computed, otherwise (the public key of the certificate cannot be read) - <see langword="false" />.</returns>
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "RFC 5280 §4.2.1.2 method (1) defines the key identifier as a SHA-1 hash; it is a lookup key for the FIDO Metadata Service, not a security hash")]
    protected virtual bool TryComputeAttestationCertificateKeyIdentifier(X509Certificate2 attCert, [NotNullWhen(true)] out byte[]? keyIdentifier)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attCert is null)
        {
            keyIdentifier = null;
            return false;
        }

        try
        {
            // PublicKey.EncodedKeyValue holds the value of the subjectPublicKey BIT STRING without the tag, length and unused-bits octet
            keyIdentifier = SHA1.HashData(attCert.PublicKey.EncodedKeyValue.RawData);
            return true;
        }
        catch (CryptographicException)
        {
            keyIdentifier = null;
            return false;
        }
    }

    /// <summary>
    ///     Retrieves the certificate's subject key identifier (SKI) if it is present.
    /// </summary>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <returns>
    ///     If the certificate has a subject key identifier - the result will contain a byte array, if the certificate does not have a subject key identifier, the result will contain <see langword="null" />. Otherwise, it will indicate that an error occurred during the retrieval of
    ///     the subject key identifier.
    /// </returns>
    protected virtual Result<byte[]?> GetSubjectKeyIdentifierIfExists(X509Certificate2 attCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attCert is null)
        {
            return Result<byte[]?>.Fail();
        }

        var subjectKeyIdentifierExtension = attCert.Extensions.FirstOrDefault(static x => x is X509SubjectKeyIdentifierExtension);
        if (subjectKeyIdentifierExtension is X509SubjectKeyIdentifierExtension skiExtension)
        {
            try
            {
                // the typed extension decodes its value lazily and throws for a malformed value; the certificate is client-supplied, so this is a failure, not an exception
                var binarySki = skiExtension.SubjectKeyIdentifierBytes;
                if (binarySki.Length > 0)
                {
                    return Result<byte[]?>.Success(binarySki.ToArray());
                }
            }
            catch (CryptographicException exception)
            {
                Logger.FidoU2FAttCertSubjectKeyIdentifierMalformed(exception);
                return Result<byte[]?>.Fail();
            }
        }

        return Result<byte[]?>.Success(null);
    }

    /// <summary>
    ///     Retrieves the aaguid from the certificate if it is present.
    /// </summary>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <returns>If the certificate has an aaguid - the result will contain a <see cref="Guid" />, if the certificate doesn't have an aaguid, the result will contain <see langword="null" />. Otherwise, it will indicate that an error occurred during the retrieval of the aaguid.</returns>
    protected virtual Result<Guid?> GetAaguidIfExists(X509Certificate2 attCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attCert is null)
        {
            return Result<Guid?>.Fail();
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
    ///     Verifies the public key parameters and returns its out parameter ><paramref name="attCertEcParameters" /> as the .NET built-in type <see cref="ECParameters" />, if they contain correct values.
    /// </summary>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="attCertEcParameters">Output parameter. If the method returns true, it contains public key parameters; otherwise - <see langword="null" />.</param>
    /// <returns>If the public key parameters are correct - returns <see langword="true" />, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool IsValidPublicKeyParameters(X509Certificate2 attCert, [NotNullWhen(true)] out ECParameters? attCertEcParameters)
    {
        //  If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
        if (attCert is null)
        {
            attCertEcParameters = null;
            return false;
        }

        using var ecDsaPubKey = attCert.GetECDsaPublicKey();
        if (ecDsaPubKey is null)
        {
            attCertEcParameters = null;
            return false;
        }

        ECParameters parameters;
        try
        {
            parameters = ecDsaPubKey.ExportParameters(false);
        }
        catch (CryptographicException)
        {
            attCertEcParameters = null;
            return false;
        }

        // A key with explicit curve parameters (RFC 3279 §2.3.5 'specifiedCurve') has no OID: ECCurve.Oid is null unless the curve is a named one.
        // Only the named P-256 curve is acceptable, so such a key is rejected (instead of dereferencing the null OID).
        if (!parameters.Curve.IsNamed || parameters.Curve.Oid?.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            attCertEcParameters = null;
            return false;
        }

        attCertEcParameters = parameters;
        return true;
    }

    /// <summary>
    ///     Converts the public key from COSE format to Raw ANSI X9.62 public key format.
    /// </summary>
    /// <param name="credentialPublicKey">Public key in COSE format.</param>
    /// <param name="publicKeyU2F">Output parameter. If conversion was successful - contains a key in Raw ANSI X9.62 format as a byte array, otherwise - <see langword="null" />.</param>
    /// <returns>If the conversion was successful - returns <see langword="true" />, otherwise - <see langword="false" />.</returns>
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

    /// <summary>
    ///     Concatenates three ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <param name="c">Third ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        var result = new byte[a.Length + b.Length + c.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        return result;
    }

    /// <summary>
    ///     Concatenates five ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <param name="c">Third ReadOnlySpan of bytes.</param>
    /// <param name="d">Fourth ReadOnlySpan of bytes.</param>
    /// <param name="e">Fifth ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        var result = new byte[a.Length + b.Length + c.Length + d.Length + e.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        d.CopyTo(result.AsSpan(a.Length + b.Length + c.Length));
        e.CopyTo(result.AsSpan(a.Length + b.Length + c.Length + d.Length));
        return result;
    }
}

/// <summary>
///     Extension methods for logging the FIDO U2F attestation statement verifier.
/// </summary>
public static partial class DefaultFidoU2FAttestationStatementVerifierLoggingExtensions
{
    /// <summary>
    ///     The 'x5c' of the FIDO U2F attestation statement contains {Count} element(s), but exactly one (attCert) is expected
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of elements in 'x5c'.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' of the FIDO U2F attestation statement contains {Count} element(s), but exactly one (attCert) is expected")]
    public static partial void FidoU2FX5CNotSingleElement(this ILogger logger, int count);

    /// <summary>
    ///     Failed to load the attCert of the FIDO U2F attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to load the attCert of the FIDO U2F attestation statement")]
    public static partial void FidoU2FAttCertInvalid(this ILogger logger);

    /// <summary>
    ///     The attCert of the FIDO U2F attestation statement is not valid at the current time
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The attCert of the FIDO U2F attestation statement is not valid at the current time")]
    public static partial void FidoU2FAttCertNotValidNow(this ILogger logger);

    /// <summary>
    ///     The public key of the attCert of the FIDO U2F attestation statement is not an Elliptic Curve public key over the named P-256 curve
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The public key of the attCert of the FIDO U2F attestation statement is not an Elliptic Curve public key over the named P-256 curve")]
    public static partial void FidoU2FAttCertPublicKeyNotP256(this ILogger logger);

    /// <summary>
    ///     The credential public key of the FIDO U2F attestation statement is not an EC2 COSE key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The credential public key of the FIDO U2F attestation statement is not an EC2 COSE key")]
    public static partial void FidoU2FCredentialPublicKeyNotEc2(this ILogger logger);

    /// <summary>
    ///     The coordinates of the credential public key of the FIDO U2F attestation statement are {XLength} and {YLength} byte(s) long, but 32 bytes each are expected
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="xLength">The length of the x coordinate.</param>
    /// <param name="yLength">The length of the y coordinate.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The coordinates of the credential public key of the FIDO U2F attestation statement are {XLength} and {YLength} byte(s) long, but 32 bytes each are expected")]
    public static partial void FidoU2FCredentialPublicKeyCoordinatesInvalid(this ILogger logger, int xLength, int yLength);

    /// <summary>
    ///     The 'sig' of the FIDO U2F attestation statement is not a valid signature over verificationData made with the public key of attCert
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'sig' of the FIDO U2F attestation statement is not a valid signature over verificationData made with the public key of attCert")]
    public static partial void FidoU2FSignatureInvalid(this ILogger logger);

    /// <summary>
    ///     The FIDO Metadata Service has no usable metadata for the aaguid {Aaguid} of the FIDO U2F attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service has no usable metadata for the aaguid {Aaguid} of the FIDO U2F attestation statement")]
    public static partial void FidoU2FMetadataNotFoundByAaguid(this ILogger logger, Guid aaguid);

    /// <summary>
    ///     The FIDO Metadata Service entry for the aaguid {Aaguid} of the FIDO U2F attestation statement doesn't allow to trust the authenticator
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service entry for the aaguid {Aaguid} of the FIDO U2F attestation statement doesn't allow to trust the authenticator")]
    public static partial void FidoU2FMetadataUntrustedByAaguid(this ILogger logger, Guid aaguid);

    /// <summary>
    ///     The aaguid {AuthenticatorDataAaguid} of the authenticator data differs from the aaguid {AaguidExtension} of the id-fido-gen-ce-aaguid extension of the attCert of the FIDO U2F attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="authenticatorDataAaguid">The aaguid of the authenticator data, which the FIDO U2F attestation signature doesn't cover.</param>
    /// <param name="aaguidExtension">The aaguid of the id-fido-gen-ce-aaguid extension of the attCert.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The aaguid {AuthenticatorDataAaguid} of the authenticator data differs from the aaguid {AaguidExtension} of the id-fido-gen-ce-aaguid extension of the attCert of the FIDO U2F attestation statement")]
    public static partial void FidoU2FAuthenticatorDataAaguidMismatch(this ILogger logger, Guid authenticatorDataAaguid, Guid aaguidExtension);

    /// <summary>
    ///     The id-fido-gen-ce-aaguid extension of the attCert of the FIDO U2F attestation statement is invalid
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The id-fido-gen-ce-aaguid extension of the attCert of the FIDO U2F attestation statement is invalid")]
    public static partial void FidoU2FAttCertAaguidExtensionInvalid(this ILogger logger);

    /// <summary>
    ///     The RFC 5280 §4.2.1.2 key identifier of the attCert of the FIDO U2F attestation statement cannot be computed: the public key cannot be read
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The RFC 5280 §4.2.1.2 key identifier of the attCert of the FIDO U2F attestation statement cannot be computed: the public key cannot be read")]
    public static partial void FidoU2FAttCertKeyIdentifierNotComputable(this ILogger logger);

    /// <summary>
    ///     The Subject Key Identifier extension of the attCert of the FIDO U2F attestation statement is malformed
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception thrown while decoding the extension.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The Subject Key Identifier extension of the attCert of the FIDO U2F attestation statement is malformed")]
    public static partial void FidoU2FAttCertSubjectKeyIdentifierMalformed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The FIDO Metadata Service has no usable metadata for the attestation certificate key identifier {KeyIdentifier} of the FIDO U2F attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="keyIdentifier">The RFC 5280 §4.2.1.2 method (1) key identifier of the attCert, as a hex string.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service has no usable metadata for the attestation certificate key identifier {KeyIdentifier} of the FIDO U2F attestation statement")]
    public static partial void FidoU2FMetadataNotFoundByKeyIdentifier(this ILogger logger, string keyIdentifier);

    /// <summary>
    ///     The FIDO Metadata Service has no usable metadata for the aaguid {Aaguid} from the id-fido-gen-ce-aaguid extension of the attCert, nor for the attestation certificate key identifier {KeyIdentifier} of the FIDO U2F attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID from the id-fido-gen-ce-aaguid extension of the attCert.</param>
    /// <param name="keyIdentifier">The RFC 5280 §4.2.1.2 method (1) key identifier of the attCert, as a hex string.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service has no usable metadata for the aaguid {Aaguid} from the id-fido-gen-ce-aaguid extension of the attCert, nor for the attestation certificate key identifier {KeyIdentifier} of the FIDO U2F attestation statement")]
    public static partial void FidoU2FMetadataNotFoundByAaguidAndKeyIdentifier(this ILogger logger, Guid aaguid, string keyIdentifier);

    /// <summary>
    ///     The FIDO Metadata Service entry for the attestation certificate key identifier {KeyIdentifier} of the FIDO U2F attestation statement doesn't allow to trust the authenticator
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="keyIdentifier">The key identifier of the attCert by which the entry was found, as a hex string.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service entry for the attestation certificate key identifier {KeyIdentifier} of the FIDO U2F attestation statement doesn't allow to trust the authenticator")]
    public static partial void FidoU2FMetadataUntrustedByKeyIdentifier(this ILogger logger, string keyIdentifier);

    /// <summary>
    ///     The metadata of the authenticator lists no attestation type that a FIDO U2F attestation statement can convey (attca or basic_full)
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The metadata of the authenticator lists no attestation type that a FIDO U2F attestation statement can convey (attca or basic_full)")]
    public static partial void FidoU2FMetadataAttestationTypesNotSupported(this ILogger logger);
}
