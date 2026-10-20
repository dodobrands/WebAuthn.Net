using System;
using System.Collections.Generic;
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
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Packed;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Packed.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Packed;

/// <summary>
///     Default implementation of <see cref="IPackedAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultPackedAttestationStatementVerifier<TContext> :
    IPackedAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultPackedAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="signatureVerifier">Digital signature verifier.</param>
    /// <param name="asn1Deserializer">ASN.1 format deserializer.</param>
    /// <param name="fidoMetadataSearchService">A service for searching in the data provided by the FIDO Metadata Service.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultPackedAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier,
        IAsn1Deserializer asn1Deserializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService,
        ILogger<DefaultPackedAttestationStatementVerifier<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(asn1Deserializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        ArgumentNullException.ThrowIfNull(logger);
        TimeProvider = timeProvider;
        SignatureVerifier = signatureVerifier;
        Asn1Deserializer = asn1Deserializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
        Logger = logger;
    }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Digital signature verifier.
    /// </summary>
    protected IDigitalSignatureVerifier SignatureVerifier { get; }

    /// <summary>
    ///     ASN.1 format deserializer.
    /// </summary>
    protected IAsn1Deserializer Asn1Deserializer { get; }

    /// <summary>
    ///     A service for searching in the data provided by the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultPackedAttestationStatementVerifier<TContext>> Logger { get; }

    /// <inheritdoc />
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        PackedAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
        // "Packed Attestation Statement Format"

        ArgumentNullException.ThrowIfNull(attStmt);
        cancellationToken.ThrowIfCancellationRequested();
        // 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) If x5c is present:
        if (attStmt.X5C is not null)
        {
            var certificatesToDispose = new List<X509Certificate2>();
            try
            {
                if (attStmt.X5C.Length == 0)
                {
                    Logger.PackedX5CEmpty();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                var currentDate = TimeProvider.GetPreciseUtcDateTime();
                var x5CCertificates = new List<X509Certificate2>(attStmt.X5C.Length);
                foreach (var x5CBytes in attStmt.X5C)
                {
                    if (!X509CertificateInMemoryLoader.TryLoad(x5CBytes, out var x5CCert))
                    {
                        x5CCert?.Dispose();
                        Logger.PackedX5CCertificateInvalid();
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    certificatesToDispose.Add(x5CCert);
                    x5CCertificates.Add(x5CCert);
                    if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                    {
                        Logger.PackedX5CCertificateNotValidNow();
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    if (IsRootCertificate(x5CCert))
                    {
                        Logger.PackedX5CContainsSelfSignedCertificate();
                        return Result<VerifiedAttestationStatement>.Fail();
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

    /// <summary>
    ///     Checks whether the provided certificate is a Root CA.
    /// </summary>
    /// <param name="cert">x509v3 certificate to be checked</param>
    /// <returns>If the certificate is a Root CA, returns <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsRootCertificate(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        return cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData.AsSpan());
    }

    /// <summary>
    ///     Performs verification steps according to the WebAuthn specification for the case when x5c is specified.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attStmt">Decoded <a href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">Packed attestation statement</a>.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="clientDataHash">SHA256 hash of <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a>.</param>
    /// <param name="certificates"><a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">Attestation trust path</a> as a readonly collection of <see cref="X509Certificate2" />.</param>
    /// <param name="trustPath">Raw <a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">attestation trust path</a> as an array of byte arrays containing x509v3 certificates.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the verification is successful - the result containing <see cref="VerifiedAttestationStatement" />, otherwise - the result indicating that the validation has failed.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual async Task<Result<VerifiedAttestationStatement>> VerifyPackedWithX5CAsync(
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
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // If x5c is present
        // 1) Verify that 'sig' is a valid signature over the concatenation of 'authenticatorData' and 'clientDataHash'
        // using the attestation public key in 'attestnCert' with the algorithm specified in 'alg'.

        // The attestation certificate 'attestnCert' MUST be the first element in the array.
        var attestnCert = certificates.First();
        var dataToVerify = Concat(authenticatorData.Raw, clientDataHash);
        if (!SignatureVerifier.IsValidCertificateSign(attestnCert, attStmt.Alg, dataToVerify, attStmt.Sig))
        {
            Logger.PackedSignatureInvalid();
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 2) Verify that 'attestnCert' meets the requirements in
        // "Certificate Requirements for Packed Attestation Statements"
        // https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements
        // (IsAttestnCertValid logs the requirement that is not met)
        if (!IsAttestnCertValid(attestnCert, out var aaguid))
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 3) If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
        // verify that the value of this extension matches the 'aaguid' in 'authenticatorData'.
        if (aaguid.HasValue && authenticatorData.AttestedCredentialData.Aaguid != aaguid.Value)
        {
            Logger.PackedAttestnCertAaguidMismatch();
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 4) Optionally, inspect 'x5c' and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.
        // (GetAttestationTypeAsync logs why the attestation type could not be determined)
        var attestationTypeResult = await GetAttestationTypeAsync(
            context,
            attestnCert,
            authenticatorData,
            cancellationToken);
        if (attestationTypeResult.HasError)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 5) If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path 'x5c'.
        var result = new VerifiedAttestationStatement(
            AttestationStatementFormat.Packed,
            attestationTypeResult.Ok.AttestationType,
            trustPath,
            new(attestationTypeResult.Ok.AttestationRootCertificates));
        return Result<VerifiedAttestationStatement>.Success(result);
    }

    /// <summary>
    ///     Returns the <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">attestation type</a> of the <a href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">Packed attestation statement</a>.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attestnCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If the <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">attestation type</a> was successfully determined and a list of Root CA certificates was obtained, the result contains a <see cref="FidoPackedAttestationTypeResult" />. Otherwise, the result
    ///     indicates that an error occurred during the execution of this operation.
    /// </returns>
    protected virtual async Task<Result<FidoPackedAttestationTypeResult>> GetAttestationTypeAsync(
        TContext context,
        X509Certificate2 attestnCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();
        var metadata = await FidoMetadataSearchService.FindMetadataByAaguidAsync(
            context,
            authenticatorData.AttestedCredentialData.Aaguid,
            cancellationToken);
        if (metadata is null)
        {
            Logger.PackedMetadataNotFound(authenticatorData.AttestedCredentialData.Aaguid);
            return Result<FidoPackedAttestationTypeResult>.Fail();
        }

        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_ATTCA))
        {
            var rootCertificates = new UniqueByteArraysCollection();
            rootCertificates.AddRange(metadata.RootCertificates);
            return Result<FidoPackedAttestationTypeResult>.Success(new(AttestationType.AttCa, rootCertificates));
        }

        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            var rootCertificates = new UniqueByteArraysCollection();
            rootCertificates.AddRange(metadata.RootCertificates);
            return Result<FidoPackedAttestationTypeResult>.Success(new(AttestationType.Basic, rootCertificates));
        }

        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_SURROGATE))
        {
            var rootCertificates = new UniqueByteArraysCollection();
            rootCertificates.AddRange(metadata.RootCertificates);
            return Result<FidoPackedAttestationTypeResult>.Success(new(AttestationType.Self, rootCertificates));
        }

        Logger.PackedMetadataAttestationTypesNotSupported(authenticatorData.AttestedCredentialData.Aaguid);
        return Result<FidoPackedAttestationTypeResult>.Fail();
    }

    /// <summary>
    ///     Performs verification steps according to the WebAuthn specification for the case when x5c is not specified.
    /// </summary>
    /// <param name="attStmt">Decoded <a href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">Packed attestation statement</a>.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="clientDataHash">SHA256 hash of <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a>.</param>
    /// <returns>If the verification is successful - the result containing <see cref="VerifiedAttestationStatement" />, otherwise - the result indicating that the validation has failed.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual Result<VerifiedAttestationStatement> VerifyPackedWithoutX5C(
        PackedAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash)
    {
        if (attStmt is null || authenticatorData is null)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // If x5c is not present, self attestation is in use.
        // 1) Validate that 'alg' matches the algorithm of the 'credentialPublicKey' in 'authenticatorData'.
        if (attStmt.Alg != authenticatorData.AttestedCredentialData.CredentialPublicKey.Alg)
        {
            Logger.PackedSelfAlgMismatch((int) attStmt.Alg, (int) authenticatorData.AttestedCredentialData.CredentialPublicKey.Alg);
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 2) Verify that 'sig' is a valid signature over the concatenation of 'authenticatorData' and 'clientDataHash'
        // using the credential public key with 'alg'.
        var dataToVerify = Concat(authenticatorData.Raw, clientDataHash);
        if (!SignatureVerifier.IsValidCoseKeySign(authenticatorData.AttestedCredentialData.CredentialPublicKey, dataToVerify, attStmt.Sig))
        {
            Logger.PackedSelfSignatureInvalid();
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 3) If successful, return implementation-specific values representing attestation type Self and an empty attestation trust path.
        var result = new VerifiedAttestationStatement(
            AttestationStatementFormat.Packed,
            AttestationType.Self,
            null,
            null);
        return Result<VerifiedAttestationStatement>.Success(result);
    }

    /// <summary>
    ///     Validates the attestation certificate and, in case of success, returns the aaguid if it was encoded in the certificate (or <see langword="null" />, if it was not).
    /// </summary>
    /// <param name="attestnCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="aaguid">Output parameter. The AAGUID of the authenticator. Can be <see langword="null" />.</param>
    /// <returns>
    ///     If the attestation certificate is valid - returns <see langword="true" />, as well as the AAGUID of the authenticator in the out parameter <paramref name="aaguid" /> (if it's encoded as an extension of the attestation certificate, and in case the certificate doesn't
    ///     have the corresponding extension, it may return <see langword="null" /> which is a normal behavior). Otherwise - returns <see langword="false" />.
    /// </returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool IsAttestnCertValid(X509Certificate2 attestnCert, out Guid? aaguid)
    {
        // "Certificate Requirements for Packed Attestation Statements"
        // https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements

        if (attestnCert is null)
        {
            aaguid = null;
            return false;
        }

        // 1 - Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
        if (attestnCert.Version != 3)
        {
            Logger.PackedAttestnCertRequirementNotMet("version");
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
            Logger.PackedAttestnCertRequirementNotMet("subject");
            aaguid = null;
            return false;
        }

        // 3 - If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING.
        // The extension MUST NOT be marked as critical.
        var aaguidResult = GetAaguidIfExists(attestnCert);
        if (aaguidResult.HasError)
        {
            Logger.PackedAttestnCertRequirementNotMet("id-fido-gen-ce-aaguid extension");
            aaguid = null;
            return false;
        }

        // 4 - The Basic Constraints extension MUST have the CA component set to false.
        if (!IsBasicExtensionsCaComponentFalse(attestnCert))
        {
            Logger.PackedAttestnCertRequirementNotMet("basic constraints");
            aaguid = null;
            return false;
        }

        // 5 - An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280]
        // are both OPTIONAL as the status of many attestation certificates is available through authenticator metadata services.
        // See, for example, the FIDO Metadata Service [FIDOMetadataService].
        aaguid = aaguidResult.Ok;
        return true;
    }

    /// <summary>
    ///     Validates the correctness of the subject in the attestation certificate.
    /// </summary>
    /// <param name="subjectName">Subject from the attestation certificate.</param>
    /// <returns>If the subject is correct - <see langword="true" />, otherwise - <see langword="false" />.</returns>
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
        string subjectString;
        try
        {
            subjectString = subjectName.Decode(X500DistinguishedNameFlags.UseNewLines);
        }
        catch (CryptographicException exception)
        {
            // the subject comes from a client-supplied certificate: a name that the platform loaded but the decoder cannot represent is a failed requirement, not an exception
            Logger.PackedAttestnCertSubjectMalformed(exception);
            return false;
        }

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

    /// <summary>
    ///     Retrieves the aaguid from the certificate if it is present.
    /// </summary>
    /// <param name="attestnCert">Attestation certificate in the x509v3 format.</param>
    /// <returns>If the certificate has an aaguid - the result will contain a <see cref="Guid" />, if the certificate doesn't have an aaguid, the result will contain <see langword="null" />. Otherwise, it will indicate that an error occurred during the retrieval of the aaguid.</returns>
    protected virtual Result<Guid?> GetAaguidIfExists(X509Certificate2 attestnCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attestnCert is null)
        {
            return Result<Guid?>.Fail();
        }

        // If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
        // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
        // Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
        var extension = attestnCert.Extensions.FirstOrDefault(static x => x.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
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
    ///     Validates that the Basic Constraints extension has the CA component set to false.
    /// </summary>
    /// <param name="attestnCert">Attestation certificate in the x509v3 format.</param>
    /// <returns><see langword="true" /> if the Basic Constraints extension has the CA component set to false, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsBasicExtensionsCaComponentFalse(X509Certificate2 attestnCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attestnCert is null)
        {
            return false;
        }

        // The Basic Constraints extension MUST have the CA component set to false.
        var extension = attestnCert.Extensions.FirstOrDefault(static e => e.Oid?.Value is "2.5.29.19");
        if (extension is X509BasicConstraintsExtension basicExtension)
        {
            try
            {
                // the typed extension decodes its value lazily and throws for a malformed value; the certificate is client-supplied, so this is a failed requirement, not an exception
                var isCaCert = basicExtension.CertificateAuthority;
                var isCaComponentFalse = !isCaCert;
                return isCaComponentFalse;
            }
            catch (CryptographicException exception)
            {
                Logger.PackedAttestnCertBasicConstraintsMalformed(exception);
                return false;
            }
        }

        return false;
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

/// <summary>
///     Extension methods for logging the Packed attestation statement verifier.
/// </summary>
public static partial class DefaultPackedAttestationStatementVerifierLoggingExtensions
{
    /// <summary>
    ///     The 'x5c' of the Packed attestation statement is present but empty
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' of the Packed attestation statement is present but empty")]
    public static partial void PackedX5CEmpty(this ILogger logger);

    /// <summary>
    ///     Failed to load a certificate from the 'x5c' of the Packed attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to load a certificate from the 'x5c' of the Packed attestation statement")]
    public static partial void PackedX5CCertificateInvalid(this ILogger logger);

    /// <summary>
    ///     A certificate from the 'x5c' of the Packed attestation statement is not valid at the current time
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "A certificate from the 'x5c' of the Packed attestation statement is not valid at the current time")]
    public static partial void PackedX5CCertificateNotValidNow(this ILogger logger);

    /// <summary>
    ///     The 'x5c' of the Packed attestation statement contains a self-signed (root) certificate
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' of the Packed attestation statement contains a self-signed (root) certificate")]
    public static partial void PackedX5CContainsSelfSignedCertificate(this ILogger logger);

    /// <summary>
    ///     The 'sig' of the Packed attestation statement is not a valid signature over authenticatorData || clientDataHash made with the attestation public key of attestnCert and the algorithm 'alg'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'sig' of the Packed attestation statement is not a valid signature over authenticatorData || clientDataHash made with the attestation public key of attestnCert and the algorithm 'alg'")]
    public static partial void PackedSignatureInvalid(this ILogger logger);

    /// <summary>
    ///     The attestnCert of the Packed attestation statement does not meet the Packed Attestation Statement Certificate Requirements: {Requirement}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="requirement">The requirement that is not met.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The attestnCert of the Packed attestation statement does not meet the Packed Attestation Statement Certificate Requirements: {Requirement}")]
    public static partial void PackedAttestnCertRequirementNotMet(this ILogger logger, string requirement);

    /// <summary>
    ///     The subject of the attestnCert of the Packed attestation statement cannot be decoded
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception thrown while decoding the subject.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The subject of the attestnCert of the Packed attestation statement cannot be decoded")]
    public static partial void PackedAttestnCertSubjectMalformed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The Basic Constraints extension of the attestnCert of the Packed attestation statement is malformed
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception thrown while decoding the extension.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The Basic Constraints extension of the attestnCert of the Packed attestation statement is malformed")]
    public static partial void PackedAttestnCertBasicConstraintsMalformed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The id-fido-gen-ce-aaguid extension of the attestnCert of the Packed attestation statement does not match the aaguid in authenticatorData
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The id-fido-gen-ce-aaguid extension of the attestnCert of the Packed attestation statement does not match the aaguid in authenticatorData")]
    public static partial void PackedAttestnCertAaguidMismatch(this ILogger logger);

    /// <summary>
    ///     The FIDO Metadata Service has no trusted metadata for the aaguid {Aaguid} of the Packed attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service has no trusted metadata for the aaguid {Aaguid} of the Packed attestation statement")]
    public static partial void PackedMetadataNotFound(this ILogger logger, Guid aaguid);

    /// <summary>
    ///     The metadata of the aaguid {Aaguid} lists no attestation type that a Packed attestation statement with 'x5c' can convey (attca, basic_full or basic_surrogate)
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The metadata of the aaguid {Aaguid} lists no attestation type that a Packed attestation statement with 'x5c' can convey (attca, basic_full or basic_surrogate)")]
    public static partial void PackedMetadataAttestationTypesNotSupported(this ILogger logger, Guid aaguid);

    /// <summary>
    ///     The 'alg' {Alg} of the Packed self attestation statement does not match the algorithm {CredentialPublicKeyAlg} of the credential public key
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="alg">The 'alg' of the attestation statement.</param>
    /// <param name="credentialPublicKeyAlg">The algorithm of the credential public key.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'alg' {Alg} of the Packed self attestation statement does not match the algorithm {CredentialPublicKeyAlg} of the credential public key")]
    public static partial void PackedSelfAlgMismatch(this ILogger logger, int alg, int credentialPublicKeyAlg);

    /// <summary>
    ///     The 'sig' of the Packed self attestation statement is not a valid signature over authenticatorData || clientDataHash made with the credential public key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'sig' of the Packed self attestation statement is not a valid signature over authenticatorData || clientDataHash made with the credential public key")]
    public static partial void PackedSelfSignatureInvalid(this ILogger logger);
}
